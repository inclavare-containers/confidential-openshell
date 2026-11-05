// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use clap::{ArgAction, Parser};
use miette::{IntoDiagnostic, Result};
use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use tracing::info;

use openshell_core::VERSION;
use openshell_core::proto::compute::v1::compute_driver_server::ComputeDriverServer;
use openshell_driver_confidential_kubernetes::{
    ComputeDriverService, ConfidentialDriverSettings, DEFAULT_GATEWAY_ID,
    DEFAULT_SANDBOX_SERVICE_ACCOUNT_NAME, KubernetesComputeConfig, KubernetesComputeDriver,
    KubernetesImagePullPolicy, KubernetesSandboxRuntimeConfig, ManagedSshIngressConfig,
    WorkspaceMode,
};

#[derive(Parser, Debug)]
#[command(name = "openshell-driver-confidential-kubernetes")]
#[command(version = VERSION)]
#[allow(clippy::struct_excessive_bools)]
struct Args {
    /// Time budget for policy generation, guest boot and image preparation.
    #[arg(long, env = "OPENSHELL_BOOTSTRAP_TIMEOUT_SECONDS", default_value_t = 300,
        value_parser = clap::value_parser!(u64).range(1..=3600))]
    bootstrap_timeout_seconds: u64,

    /// `RuntimeClass` backed by an attested confidential guest for both Pods.
    #[arg(long, env = "OPENSHELL_CONFIDENTIAL_RUNTIME_CLASS")]
    confidential_runtime_class: String,

    /// Base Kata initdata TOML; role and generation binding is added per Pod.
    #[arg(long, env = "OPENSHELL_GUEST_INITDATA_BASE")]
    guest_initdata_base: PathBuf,

    /// Trusted host gateway CA, sealed into the supervisor bootstrap Secret.
    #[arg(long, env = "OPENSHELL_CONFIDENTIAL_CLIENT_TLS_CA")]
    confidential_client_tls_ca: PathBuf,

    /// Trusted policy generator that verifies admitted Pods against T's launch intent.
    #[arg(long, env = "OPENSHELL_KATA_POLICY_GENERATOR")]
    kata_policy_generator: PathBuf,

    #[arg(long, env = "OPENSHELL_KATA_POLICY_TOOLS_DIR")]
    kata_policy_tools_dir: PathBuf,

    /// Optional additional registry CA; system roots remain enabled.
    #[arg(long, env = "OPENSHELL_KATA_POLICY_REGISTRY_CA")]
    kata_policy_registry_ca: Option<PathBuf>,

    /// Immutable pause image used by Kata policy generation.
    #[arg(long, env = "OPENSHELL_KATA_POLICY_PAUSE_IMAGE")]
    kata_policy_pause_image: String,

    /// Private driver publication staging; never shared with Trustee.
    #[arg(long, env = "OPENSHELL_BOOTSTRAP_STORE_DIR")]
    bootstrap_store_dir: PathBuf,

    #[arg(long, env = "OPENSHELL_BOOTSTRAP_SIGNING_KEY")]
    bootstrap_signing_key: PathBuf,

    #[arg(long, env = "OPENSHELL_KBS_POLICY_RENDERER")]
    kbs_policy_renderer: PathBuf,

    #[arg(long, env = "OPENSHELL_KBS_POLICY_OUTPUT")]
    kbs_policy_output: PathBuf,

    #[arg(long, env = "OPENSHELL_AS_POLICY_OUTPUT")]
    as_policy_output: PathBuf,

    /// Authenticated KBS management endpoint and private admin key configuration.
    #[arg(long, env = "OPENSHELL_TRUSTEE_CONFIG")]
    trustee_config: PathBuf,

    /// Display passive historical Trustee appraisals in native sandbox conditions.
    #[arg(long, env = "OPENSHELL_ATTESTATION_REPORTS", default_value_t = false)]
    attestation_reports: bool,

    /// Operator-owned JSON policy; omitted means driver config disabled and labels required.
    #[arg(
        long,
        env = "OPENSHELL_DRIVER_ADMISSION_CONFIG_JSON",
        default_value = "{}"
    )]
    admission_config_json: openshell_core::resource_admission::DriverAdmissionConfig,
    /// Public compute-driver Unix socket used by an external gateway.
    #[arg(long, env = "OPENSHELL_COMPUTE_DRIVER_SOCKET")]
    bind_socket: Option<PathBuf>,

    #[arg(
        long,
        env = "OPENSHELL_COMPUTE_DRIVER_BIND",
        default_value = "127.0.0.1:50061"
    )]
    bind_address: SocketAddr,

    #[arg(long, env = "OPENSHELL_LOG_LEVEL", default_value = "info")]
    log_level: String,

    #[arg(long, env = "OPENSHELL_OTLP_ENDPOINT")]
    otlp_endpoint: Option<String>,

    /// OTLP/gRPC collector endpoint for supervisor OCSF event export.
    #[arg(long, env = "OPENSHELL_OTLP_OCSF_ENDPOINT")]
    otlp_ocsf_endpoint: Option<String>,

    /// OCSF schema version that supervisors downgrade exported events to.
    #[arg(
        long,
        env = "OPENSHELL_OTLP_OCSF_SCHEMA_VERSION",
        requires = "otlp_ocsf_endpoint"
    )]
    otlp_ocsf_schema_version: Option<String>,

    #[arg(long, env = "OPENSHELL_GATEWAY_NAME")]
    gateway_name: Option<String>,

    #[arg(long, env = "OPENSHELL_WORKSPACE_MODE", default_value = "shared")]
    workspace_mode: WorkspaceMode,

    #[arg(
        long,
        env = "OPENSHELL_GATEWAY_ID",
        default_value = DEFAULT_GATEWAY_ID
    )]
    gateway_id: String,

    #[arg(long, env = "OPENSHELL_SANDBOX_NAMESPACE", default_value = "default")]
    sandbox_namespace: String,

    #[arg(long, env = "OPENSHELL_OPERATOR_NAMESPACE_LABEL")]
    operator_namespace_label: Option<String>,

    #[arg(long, env = "OPENSHELL_OPERATOR_NAMESPACE_FILE")]
    operator_namespace_file: Option<String>,

    #[arg(
        long,
        env = "OPENSHELL_K8S_SANDBOX_SERVICE_ACCOUNT",
        default_value = DEFAULT_SANDBOX_SERVICE_ACCOUNT_NAME
    )]
    sandbox_service_account: String,

    #[arg(long, env = "OPENSHELL_SANDBOX_IMAGE")]
    sandbox_image: Option<String>,

    #[arg(long, env = "OPENSHELL_SANDBOX_IMAGE_PULL_POLICY")]
    sandbox_image_pull_policy: Option<KubernetesImagePullPolicy>,

    #[arg(
        long,
        env = "OPENSHELL_SANDBOX_IMAGE_PULL_SECRETS",
        value_delimiter = ','
    )]
    sandbox_image_pull_secrets: Vec<String>,

    #[arg(
        long,
        env = "OPENSHELL_K8S_ALLOWED_POD_ANNOTATIONS",
        value_delimiter = ','
    )]
    allowed_pod_annotations: Vec<String>,

    #[arg(long, env = "OPENSHELL_K8S_ALLOWED_POD_LABELS", value_delimiter = ',')]
    allowed_pod_labels: Vec<String>,

    #[arg(long, env = "OPENSHELL_MANAGED_SSH_INGRESS_ENABLED")]
    managed_ssh_ingress_enabled: bool,

    #[arg(long, env = "OPENSHELL_MANAGED_SSH_GATEWAY_NAMESPACE")]
    managed_ssh_gateway_namespace: Option<String>,

    #[arg(
        long,
        env = "OPENSHELL_MANAGED_SSH_GATEWAY_POD_SELECTOR",
        value_delimiter = ','
    )]
    managed_ssh_gateway_pod_selector: Vec<String>,

    #[arg(long, env = "OPENSHELL_GRPC_ENDPOINT")]
    grpc_endpoint: Option<String>,

    #[arg(
        long,
        env = "OPENSHELL_SANDBOX_SSH_SOCKET_PATH",
        default_value = openshell_core::container_paths::SSH_SOCKET_PATH
    )]
    sandbox_ssh_socket_path: String,

    #[arg(long, env = "OPENSHELL_HOST_GATEWAY_IP")]
    host_gateway_ip: Option<String>,

    #[arg(long, env = openshell_core::config::SANDBOX_RUNTIME_IMAGE_ENV)]
    sandbox_runtime_image: Option<String>,

    #[arg(long, env = "OPENSHELL_SANDBOX_RUNTIME_IMAGE_PULL_POLICY")]
    sandbox_runtime_image_pull_policy: Option<KubernetesImagePullPolicy>,

    #[arg(long, env = openshell_core::config::SUPERVISOR_IMAGE_ENV)]
    supervisor_image: Option<String>,

    #[arg(long, env = "OPENSHELL_SUPERVISOR_IMAGE_PULL_POLICY")]
    supervisor_image_pull_policy: Option<KubernetesImagePullPolicy>,

    #[arg(
        long,
        env = "OPENSHELL_K8S_SANDBOX_RUNTIME_BOUNDARY_PORT",
        default_value_t = 5500
    )]
    sandbox_runtime_boundary_port: u16,

    /// Corporate HTTP forward proxy for policy-approved TLS CONNECT egress.
    #[arg(long, env = "OPENSHELL_UPSTREAM_PROXY")]
    https_proxy: Option<String>,

    /// Comma-separated destinations that bypass the corporate proxy.
    #[arg(long, env = "OPENSHELL_UPSTREAM_NO_PROXY")]
    no_proxy: Option<String>,

    /// Send destination hostnames rather than validated IPs in CONNECT.
    #[arg(long, env = "OPENSHELL_UPSTREAM_PROXY_CONNECT_BY_HOSTNAME", action = ArgAction::SetTrue)]
    proxy_connect_by_hostname: bool,

    /// Path to a PEM CA bundle trusted for the corporate proxy. Required for
    /// an `https://` proxy with a private CA, and for a TLS-intercepting proxy
    /// that re-signs upstream certificates. Read by this process and staged
    /// into each sandbox's supervisor bootstrap Secret.
    #[arg(long, env = "OPENSHELL_UPSTREAM_PROXY_CA_BUNDLE")]
    proxy_ca_bundle: Option<String>,

    #[arg(long, env = "OPENSHELL_ENABLE_USER_NAMESPACES")]
    enable_user_namespaces: bool,

    #[arg(long, env = "OPENSHELL_PROVIDER_SPIFFE_WORKLOAD_API_SOCKET")]
    provider_spiffe_workload_api_socket_path: Option<String>,

    #[arg(long, env = "OPENSHELL_K8S_SANDBOX_UID")]
    sandbox_uid: Option<u32>,

    #[arg(long, env = "OPENSHELL_K8S_SANDBOX_GID")]
    sandbox_gid: Option<u32>,
}

async fn shutdown_signal() {
    #[cfg(unix)]
    {
        let terminate = async {
            match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
                Ok(mut signal) => {
                    signal.recv().await;
                }
                Err(_) => std::future::pending::<()>().await,
            }
        };
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            () = terminate => {}
        }
    }

    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    let _tracing = openshell_otel::install_driver_tracing(
        openshell_driver_confidential_kubernetes::otel_tracing::TRACING,
        openshell_otel::DriverTracingConfig {
            endpoint: args.otlp_endpoint.as_deref(),
            gateway_name: args.gateway_name.as_deref(),
            service_version: VERSION,
            log_level: &args.log_level,
        },
    );

    let managed_ssh_gateway_pod_selector = args
        .managed_ssh_gateway_pod_selector
        .iter()
        .map(|entry| {
            entry
                .split_once('=')
                .map(|(key, value)| (key.to_string(), value.to_string()))
                .ok_or_else(|| {
                    miette::miette!("managed SSH gateway pod selector must use key=value: {entry}")
                })
        })
        .collect::<Result<BTreeMap<_, _>>>()?;

    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let driver = KubernetesComputeDriver::new(
        KubernetesComputeConfig {
            supervisor_topology: None,
            shared_supervisor: None,
            allow_driver_config: args.admission_config_json.allow_driver_config,
            resource_admission: args.admission_config_json.resource_admission.clone(),
            workspace_mode: args.workspace_mode,
            gateway_id: args.gateway_id,
            namespace: args.sandbox_namespace,
            operator_namespace_label: args.operator_namespace_label,
            operator_namespace_file: args.operator_namespace_file,
            service_account_name: args.sandbox_service_account,
            default_image: args.sandbox_image.unwrap_or_default(),
            image_pull_policy: args.sandbox_image_pull_policy,
            image_pull_secrets: args.sandbox_image_pull_secrets,
            managed_ssh_ingress: ManagedSshIngressConfig {
                enabled: args.managed_ssh_ingress_enabled,
                gateway_namespace: args.managed_ssh_gateway_namespace.unwrap_or_default(),
                gateway_pod_selector: managed_ssh_gateway_pod_selector,
            },
            sandbox_runtime_image: args
                .sandbox_runtime_image
                .unwrap_or_else(openshell_core::config::default_sandbox_runtime_image),
            sandbox_runtime_image_pull_policy: args.sandbox_runtime_image_pull_policy,
            supervisor_image: args
                .supervisor_image
                .unwrap_or_else(openshell_core::config::default_supervisor_image),
            supervisor_image_pull_policy: args.supervisor_image_pull_policy,
            sandbox_runtime: KubernetesSandboxRuntimeConfig {
                boundary_port: args.sandbox_runtime_boundary_port,
            },
            https_proxy: args.https_proxy,
            no_proxy: args.no_proxy,
            proxy_auth_secret_name: None,
            proxy_auth_secret_key: None,
            proxy_auth_allow_insecure: None,
            proxy_connect_by_hostname: args.proxy_connect_by_hostname.then_some(true),
            proxy_ca_bundle: args.proxy_ca_bundle,
            grpc_endpoint: args.grpc_endpoint.unwrap_or_default(),
            supervisor_otlp_endpoint: args.otlp_endpoint.clone(),
            supervisor_gateway_name: args.gateway_name.clone(),
            supervisor_ocsf_export: args.otlp_ocsf_endpoint.clone().map(|endpoint| {
                openshell_core::sandbox_env::OcsfOtlpExport {
                    endpoint,
                    schema_version: args.otlp_ocsf_schema_version.clone(),
                }
            }),
            ssh_socket_path: args.sandbox_ssh_socket_path,
            client_tls_secret_name: String::new(),
            host_gateway_ip: args.host_gateway_ip.unwrap_or_default(),
            enable_user_namespaces: args.enable_user_namespaces,
            workspace_default_storage_size: std::env::var(
                "OPENSHELL_K8S_WORKSPACE_DEFAULT_STORAGE_SIZE",
            )
            .unwrap_or_else(|_| {
                openshell_driver_confidential_kubernetes::DEFAULT_WORKSPACE_STORAGE_SIZE.to_string()
            }),
            workspace_storage_class: std::env::var("OPENSHELL_K8S_WORKSPACE_STORAGE_CLASS")
                .unwrap_or_default(),
            default_runtime_class_name: args.confidential_runtime_class,
            allowed_pod_annotations: args.allowed_pod_annotations,
            allowed_pod_labels: args.allowed_pod_labels,
            provider_spiffe_workload_api_socket_path: args
                .provider_spiffe_workload_api_socket_path
                .unwrap_or_default(),
            sandbox_uid: args.sandbox_uid,
            sandbox_gid: args.sandbox_gid,
            ..Default::default()
        },
        shutdown_rx,
        ConfidentialDriverSettings {
            bootstrap_timeout: std::time::Duration::from_secs(args.bootstrap_timeout_seconds),
            initdata_base: args.guest_initdata_base,
            client_tls_ca: args.confidential_client_tls_ca,
            policy_generator: args.kata_policy_generator,
            policy_tools_dir: args.kata_policy_tools_dir,
            policy_registry_ca: args
                .kata_policy_registry_ca
                .or_else(|| std::env::var_os("REGISTRY_CA").map(PathBuf::from))
                .filter(|path| !path.as_os_str().is_empty()),
            policy_pause_image: args.kata_policy_pause_image,
            bootstrap_store_dir: args.bootstrap_store_dir,
            bootstrap_signing_key: args.bootstrap_signing_key,
            kbs_policy_renderer: args.kbs_policy_renderer,
            kbs_policy_output: args.kbs_policy_output,
            as_policy_output: args.as_policy_output,
            trustee_config: args.trustee_config,
            attestation_reports: args.attestation_reports,
        },
    )
    .await
    .into_diagnostic()?;

    let service = ComputeDriverServer::new(ComputeDriverService::new(driver));
    let shutdown = async move {
        shutdown_signal().await;
        let _ = shutdown_tx.send(true);
    };
    if let Some(socket_path) = args.bind_socket {
        let listener = openshell_core::external_driver_socket::bind_private(&socket_path)
            .map_err(|err| miette::miette!("{err}"))?;
        let _cleanup =
            openshell_core::external_driver_socket::SocketCleanup::new(socket_path.clone());
        info!(socket = %socket_path.display(), "Starting Kubernetes compute driver");
        tonic::transport::Server::builder()
            .layer(openshell_otel::compute_driver_rpc_layer())
            .add_service(service)
            .serve_with_incoming_shutdown(
                openshell_core::external_driver_socket::SameUidUnixIncoming::new(listener),
                shutdown,
            )
            .await
            .into_diagnostic()
    } else {
        info!(address = %args.bind_address, "Starting Kubernetes compute driver");
        tonic::transport::Server::builder()
            .layer(openshell_otel::compute_driver_rpc_layer())
            .add_service(service)
            .serve_with_shutdown(args.bind_address, shutdown)
            .await
            .into_diagnostic()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_gateway_otlp_configuration() {
        let args = Args::try_parse_from([
            "openshell-driver-confidential-kubernetes",
            "--confidential-runtime-class",
            "kata-confidential",
            "--trustee-config", "/tmp/trustee-client.json",
            "--guest-initdata-base",
            "/tmp/initdata.toml",
            "--confidential-client-tls-ca",
            "/tmp/ca.pem",
            "--kata-policy-generator",
            "/tmp/agent_policy.py",
            "--kata-policy-tools-dir",
            "/tmp/kata-policy",
            "--kata-policy-pause-image",
            "registry.internal/pause@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "--bootstrap-store-dir",
            "/tmp/repository",
            "--bootstrap-signing-key",
            "/tmp/bootstrap-signer.pem",
            "--kbs-policy-renderer",
            "/tmp/render.py",
            "--kbs-policy-output",
            "/tmp/policy.rego",
            "--as-policy-output",
            "/tmp/as-policy.rego",
            "--otlp-endpoint",
            "http://collector.example:4317",
            "--gateway-name",
            "kubernetes-dev",
        ])
        .expect("OTLP endpoint should parse");

        assert_eq!(
            args.otlp_endpoint.as_deref(),
            Some("http://collector.example:4317")
        );
        assert_eq!(args.gateway_name.as_deref(), Some("kubernetes-dev"));
        assert_eq!(args.bootstrap_timeout_seconds, 300);
        assert!(args.kata_policy_registry_ca.is_none());
    }
}
