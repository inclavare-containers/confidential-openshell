// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Role- and generation-bound Kata initdata for confidential Pods.

use std::collections::BTreeMap;
use std::io::Write as _;
use std::path::Path;

use crate::bootstrap::{BootstrapRole, BootstrapStore};
use base64::Engine as _;
use flate2::{Compression, GzBuilder};
use serde_json::json;
use sha2::{Digest, Sha256, Sha384};

pub const INITDATA_ANNOTATION: &str = "io.katacontainers.config.hypervisor.cc_init_data";
pub const BOOTSTRAP_FILENAME: &str = "openshell-bootstrap.json";
pub const WORKLOAD_KEYS: &[&str] = &["boundary.json", "tls.crt", "tls.key"];
pub const SUPERVISOR_KEYS: &[&str] = &[
    "runtime-descriptor.json",
    "auth.json",
    "proxy-ca.crt",
    "proxy-ca.key",
];

#[derive(Clone)]
pub struct GuestInitdata {
    base: toml::Value,
}

impl GuestInitdata {
    pub fn load(path: &Path) -> Result<Self, String> {
        let raw = std::fs::read_to_string(path)
            .map_err(|error| format!("read guest initdata {}: {error}", path.display()))?;
        let base: toml::Value =
            toml::from_str(&raw).map_err(|error| format!("parse guest initdata: {error}"))?;
        if base.get("version").and_then(toml::Value::as_str) != Some("0.1.0")
            || base.get("algorithm").and_then(toml::Value::as_str) != Some("sha384")
        {
            return Err("guest initdata requires version 0.1.0 and sha384".to_string());
        }
        let data = base
            .get("data")
            .and_then(toml::Value::as_table)
            .ok_or_else(|| "guest initdata requires [data]".to_string())?;
        if data
            .keys()
            .any(|key| !matches!(key.as_str(), "aa.toml" | "cdh.toml" | "policy.rego"))
        {
            return Err("base guest initdata must contain only the upstream AA, CDH and agent policy entries".to_string());
        }
        for required in ["aa.toml", "cdh.toml", "policy.rego"] {
            if data
                .get(required)
                .and_then(toml::Value::as_str)
                .is_none_or(str::is_empty)
            {
                return Err(format!("guest initdata lacks {required}"));
            }
        }
        Ok(Self { base })
    }

    pub fn with_registry_ca(mut self, ca_path: &Path) -> Result<Self, String> {
        let ca = std::fs::read_to_string(ca_path).map_err(|error| {
            format!(
                "read trusted guest registry CA {}: {error}",
                ca_path.display()
            )
        })?;
        if ca.len() > 1024 * 1024 || !ca.contains("-----BEGIN CERTIFICATE-----") {
            return Err("trusted guest registry CA must be a bounded PEM certificate".to_string());
        }
        let data = self
            .base
            .get_mut("data")
            .and_then(toml::Value::as_table_mut)
            .ok_or_else(|| "guest initdata lacks [data]".to_string())?;
        let cdh_raw = data
            .get("cdh.toml")
            .and_then(toml::Value::as_str)
            .ok_or_else(|| "guest initdata lacks cdh.toml".to_string())?;
        let mut cdh: toml::Value =
            toml::from_str(cdh_raw).map_err(|error| format!("parse cdh.toml: {error}"))?;
        let cdh_table = cdh
            .as_table_mut()
            .ok_or_else(|| "cdh.toml must be a table".to_string())?;
        let image = cdh_table
            .entry("image")
            .or_insert_with(|| toml::Value::Table(toml::map::Map::new()));
        let image_table = image
            .as_table_mut()
            .ok_or_else(|| "cdh.toml [image] must be a table".to_string())?;
        image_table.insert(
            "extra_root_certificates".to_string(),
            toml::Value::Array(vec![toml::Value::String(ca)]),
        );
        data.insert(
            "cdh.toml".to_string(),
            toml::Value::String(
                toml::to_string(&cdh).map_err(|error| format!("serialize cdh.toml: {error}"))?,
            ),
        );
        Ok(self)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn render(
        &self,
        store: &BootstrapStore,
        role: BootstrapRole,
        generation: &str,
        sandbox_id: &str,
        sandbox_resource_uid: &str,
        attempt: &str,
        namespace: &str,
        keys: &[&str],
        workspace_key_uri: Option<&str>,
        allow_workspace_initialize: bool,
        generated_policy: Option<&str>,
    ) -> Result<RenderedInitdata, String> {
        let mut resources = BTreeMap::new();
        let mut sealed_descriptor_sha256 = BTreeMap::new();
        for key in keys {
            let planned = store
                .plan_file(role, generation, sandbox_id, attempt, key)
                .map_err(|error| format!("plan confidential bootstrap resource: {error}"))?;
            resources.insert((*key).to_owned(), planned.resource_uri);
            let descriptor = store
                .seal_planned_file(role, generation, sandbox_id, attempt, key)
                .map_err(|error| format!("sign confidential bootstrap descriptor: {error}"))?;
            sealed_descriptor_sha256.insert(
                (*key).to_owned(),
                format!("{:x}", Sha256::digest(descriptor.as_bytes())),
            );
        }
        if let Some(uri) = workspace_key_uri {
            if role != BootstrapRole::Workload {
                return Err("workspace key may only be assigned to the workload".to_string());
            }
            resources.insert("workspace-key".to_string(), uri.to_string());
        }
        let bootstrap = json!({
            "schema": 1,
            "sandbox_id": sandbox_id,
            "sandbox_resource_uid": sandbox_resource_uid,
            "namespace": namespace,
            "role": role.as_str(),
            "runtime_generation": generation,
            "bootstrap_attempt": attempt,
            "resource_uris": resources,
            "sealed_descriptor_sha256": sealed_descriptor_sha256,
            "sealed_volume_destination": match role {
                BootstrapRole::Workload => "/.openshell/bootstrap-input",
                BootstrapRole::Supervisor => "/.openshell/supervisor",
            },
            "sealed_volume_container": match role {
                BootstrapRole::Workload => "openshell-sandbox-bootstrap",
                BootstrapRole::Supervisor => "supervisor",
            },
        });
        let mut document = self.base.clone();
        if let Some(policy) = generated_policy {
            if !policy.starts_with("package agent_policy") || policy.len() > 2 * 1024 * 1024 {
                return Err("generated Kata agent policy is invalid".to_string());
            }
            document["data"]
                .as_table_mut()
                .expect("validated initdata [data]")
                .insert(
                    "policy.rego".to_string(),
                    toml::Value::String(policy.to_string()),
                );
        }
        let data = document["data"]
            .as_table_mut()
            .expect("validated initdata [data]");
        if let Some(uri) = workspace_key_uri {
            if store
                .plan_workspace_key(namespace, sandbox_resource_uid)
                .map_err(|error| format!("plan workspace identity: {error}"))?
                .resource_uri
                != uri
            {
                return Err(
                    "workspace key URI does not match the namespace and Sandbox CR UID".to_string(),
                );
            }
            let disk_ids = store
                .workspace_disk_ids(namespace, sandbox_resource_uid)
                .map_err(|error| format!("read measured workspace disk binding: {error}"))?;
            if generated_policy.is_some() && disk_ids.is_empty() {
                return Err(
                    "final workload initdata requires bound workspace cloud disk IDs".to_string(),
                );
            }
            let config = toml::Value::try_from(serde_json::json!({
                "version": "0.1.0", "key_uri": uri, "allow_initialize": allow_workspace_initialize,
                "encryption_type": "luks2", "filesystem_type": "ext4", "disk_ids": disk_ids,
            }))
            .map_err(|error| format!("serialize measured workspace configuration: {error}"))?;
            data.insert(
                "workspace.toml".to_string(),
                toml::Value::String(
                    toml::to_string(&config)
                        .map_err(|error| format!("serialize workspace.toml: {error}"))?,
                ),
            );
        } else {
            data.remove("workspace.toml");
        }
        document["data"]
            .as_table_mut()
            .expect("validated initdata [data]")
            .insert(
                BOOTSTRAP_FILENAME.to_string(),
                toml::Value::String(
                    serde_json::to_string(&bootstrap).map_err(|error| error.to_string())?,
                ),
            );
        let raw = toml::to_string(&document).map_err(|error| error.to_string())?;
        let digest = format!("{:x}", Sha384::digest(raw.as_bytes()));
        let mut gzip = GzBuilder::new()
            .mtime(0)
            .write(Vec::new(), Compression::default());
        gzip.write_all(raw.as_bytes())
            .map_err(|error| format!("compress guest initdata annotation: {error}"))?;
        let compressed = gzip
            .finish()
            .map_err(|error| format!("finish guest initdata annotation: {error}"))?;
        let annotation = base64::engine::general_purpose::STANDARD.encode(compressed);
        Ok(RenderedInitdata {
            raw,
            digest,
            annotation,
        })
    }
}

pub struct RenderedInitdata {
    /// Canonical bytes measured by Kata, CAA, AAEL, and KBS. Retained for
    /// contract verification even though Kubernetes receives `annotation`.
    #[allow(dead_code)]
    pub raw: String,
    pub digest: String,
    /// Kata annotation transport: base64(gzip(raw)); never used for the AAEL digest.
    pub annotation: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read as _;

    #[test]
    fn measured_role_attempt_and_workspace_binding_change_digest() {
        let temp = std::env::temp_dir().join(format!(
            "openshell-driver-initdata-test-{}-{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        std::fs::create_dir_all(&temp).expect("create test directory");
        let base = temp.join("base.toml");
        let ca = rcgen::generate_simple_self_signed(vec!["trustee.local".to_string()])
            .expect("test CA")
            .cert
            .pem();
        let ca_path = temp.join("ca.pem");
        std::fs::write(&ca_path, &ca).expect("write CA");
        let mut data = toml::map::Map::new();
        data.insert(
            "aa.toml".to_string(),
            toml::Value::String(format!(
                "[eventlog_config]\nenable_eventlog = true\n[token_configs.kbs]\nurl = 'https://10.0.0.1:8443'\ncert = '''{ca}'''\n"
            )),
        );
        data.insert(
            "cdh.toml".to_string(),
            toml::Value::String(format!(
                "[kbc]\nname = 'cc_kbc'\nurl = 'https://10.0.0.1:8443'\nkbs_cert = '''{ca}'''\n"
            )),
        );
        data.insert(
            "policy.rego".to_string(),
            toml::Value::String("package agent_policy\ndefault allow = false\n".to_string()),
        );
        let mut base_doc = toml::map::Map::new();
        base_doc.insert(
            "version".to_string(),
            toml::Value::String("0.1.0".to_string()),
        );
        base_doc.insert(
            "algorithm".to_string(),
            toml::Value::String("sha384".to_string()),
        );
        base_doc.insert("data".to_string(), toml::Value::Table(data));
        std::fs::write(
            &base,
            toml::to_string(&toml::Value::Table(base_doc)).unwrap(),
        )
        .expect("write base initdata");
        let store = BootstrapStore::open(temp.join("repo"), temp.join("state/key.pem"))
            .expect("open test KBS store");
        let source = GuestInitdata::load(&base)
            .expect("load base initdata")
            .with_registry_ca(&ca_path)
            .expect("bind measured registry CA");
        let other_ca = temp.join("other-ca.pem");
        std::fs::write(
            &other_ca,
            rcgen::generate_simple_self_signed(vec!["other.local".to_string()])
                .unwrap()
                .cert
                .pem(),
        )
        .unwrap();
        let independent = GuestInitdata::load(&base)
            .unwrap()
            .with_registry_ca(&other_ca)
            .unwrap();
        let cdh: toml::Value =
            toml::from_str(independent.base["data"]["cdh.toml"].as_str().unwrap()).unwrap();
        assert_eq!(cdh["kbc"]["kbs_cert"].as_str().unwrap().trim(), ca.trim());
        assert_eq!(
            cdh["image"]["extra_root_certificates"][0]
                .as_str()
                .unwrap()
                .trim(),
            std::fs::read_to_string(&other_ca).unwrap().trim()
        );
        let generation = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let attempt = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
        store
            .record_workspace_owner("sandbox-1", "sandbox", "cr-uid-1")
            .unwrap();
        store
            .record_workspace_volume(
                "sandbox",
                "cr-uid-1",
                "workspace-pvc",
                Some("pv-uid"),
                Some("d-workspace"),
            )
            .unwrap();
        let workspace_uri = store
            .plan_workspace_key("sandbox", "cr-uid-1")
            .expect("plan key")
            .resource_uri;
        let workload_policy = std::env::var("OPENSHELL_TEST_WORKLOAD_POLICY")
            .ok()
            .map(std::fs::read_to_string)
            .transpose()
            .expect("read workload policy");
        let supervisor_policy = std::env::var("OPENSHELL_TEST_SUPERVISOR_POLICY")
            .ok()
            .map(std::fs::read_to_string)
            .transpose()
            .expect("read supervisor policy");
        let workload = source
            .render(
                &store,
                BootstrapRole::Workload,
                generation,
                "sandbox-1",
                "cr-uid-1",
                attempt,
                "sandbox",
                WORKLOAD_KEYS,
                Some(&workspace_uri),
                true,
                workload_policy.as_deref(),
            )
            .expect("render workload");
        let workspace: toml::Value = toml::from_str(
            toml::from_str::<toml::Value>(&workload.raw).unwrap()["data"]["workspace.toml"]
                .as_str()
                .unwrap(),
        )
        .unwrap();
        assert_eq!(
            workspace["disk_ids"].as_array().unwrap()[0].as_str(),
            Some("d-workspace")
        );
        assert_eq!(workspace["key_uri"].as_str(), Some(workspace_uri.as_str()));
        assert!(
            source
                .render(
                    &store,
                    BootstrapRole::Workload,
                    generation,
                    "sandbox-1",
                    "other-cr-uid",
                    attempt,
                    "sandbox",
                    WORKLOAD_KEYS,
                    Some(&workspace_uri),
                    false,
                    Some("package agent_policy\ndefault allow = false\n")
                )
                .is_err()
        );
        let not_bound = store
            .plan_workspace_key("sandbox", "pending-cr-uid")
            .unwrap()
            .resource_uri;
        assert!(
            source
                .render(
                    &store,
                    BootstrapRole::Workload,
                    generation,
                    "sandbox-1",
                    "pending-cr-uid",
                    attempt,
                    "sandbox",
                    WORKLOAD_KEYS,
                    Some(&not_bound),
                    false,
                    Some("package agent_policy\ndefault allow = false\n")
                )
                .is_err()
        );
        let mut supervisor_keys = SUPERVISOR_KEYS.to_vec();
        supervisor_keys.push("client-ca.crt");
        let supervisor = source
            .render(
                &store,
                BootstrapRole::Supervisor,
                generation,
                "sandbox-1",
                "cr-uid-1",
                attempt,
                "sandbox",
                &supervisor_keys,
                None,
                false,
                supervisor_policy.as_deref(),
            )
            .expect("render supervisor");
        assert_ne!(workload.digest, supervisor.digest);
        assert_eq!(
            workload.digest,
            format!("{:x}", Sha384::digest(workload.raw.as_bytes()))
        );
        assert!(workload.raw.contains("openshell-bootstrap.json"));
        assert!(workload.raw.contains(&workspace_uri));
        let workload_toml: toml::Value = toml::from_str(&workload.raw).unwrap();
        let bootstrap: serde_json::Value =
            serde_json::from_str(workload_toml["data"][BOOTSTRAP_FILENAME].as_str().unwrap())
                .unwrap();
        let hashes = bootstrap["sealed_descriptor_sha256"].as_object().unwrap();
        assert_eq!(hashes.len(), WORKLOAD_KEYS.len());
        assert_eq!(
            bootstrap["sealed_volume_destination"],
            "/.openshell/bootstrap-input"
        );
        assert_eq!(
            bootstrap["sealed_volume_container"],
            "openshell-sandbox-bootstrap"
        );
        for key in WORKLOAD_KEYS {
            let descriptor = store
                .seal_planned_file(
                    BootstrapRole::Workload,
                    generation,
                    "sandbox-1",
                    attempt,
                    key,
                )
                .unwrap();
            assert_eq!(
                hashes[*key].as_str(),
                Some(format!("{:x}", Sha256::digest(descriptor.as_bytes())).as_str())
            );
        }
        let next_attempt = "1111111111111111111111111111111111111111111111111111111111111111";
        let rotated = source
            .render(
                &store,
                BootstrapRole::Workload,
                generation,
                "sandbox-1",
                "cr-uid-1",
                next_attempt,
                "sandbox",
                WORKLOAD_KEYS,
                Some(&workspace_uri),
                false,
                None,
            )
            .expect("render rotated workload");
        assert_ne!(workload.digest, rotated.digest);
        assert_eq!(workspace["allow_initialize"].as_bool(), Some(true));
        let restarted: toml::Value = toml::from_str(
            toml::from_str::<toml::Value>(&rotated.raw).unwrap()["data"]["workspace.toml"]
                .as_str()
                .unwrap(),
        )
        .unwrap();
        assert_eq!(restarted["allow_initialize"].as_bool(), Some(false));
        let ephemeral = source
            .render(
                &store,
                BootstrapRole::Workload,
                generation,
                "sandbox-1",
                "cr-uid-1",
                attempt,
                "sandbox",
                WORKLOAD_KEYS,
                None,
                false,
                None,
            )
            .expect("render ephemeral workload");
        assert!(!ephemeral.raw.contains("workspace-key"));
        assert!(!ephemeral.raw.contains("workspace.toml"));
        for rendered in [&workload, &ephemeral, &supervisor] {
            let compressed = base64::engine::general_purpose::STANDARD
                .decode(&rendered.annotation)
                .expect("Kata standard base64 transport");
            let mut decoded = Vec::new();
            flate2::read::GzDecoder::new(compressed.as_slice())
                .read_to_end(&mut decoded)
                .expect("Kata gzip transport");
            assert_eq!(decoded, rendered.raw.as_bytes());
            assert_eq!(rendered.digest, format!("{:x}", Sha384::digest(&decoded)));
        }
        if let Ok(output) = std::env::var("OPENSHELL_INITDATA_FIXTURE_OUT") {
            std::fs::write(&output, &workload.raw).expect("write requested fixture");
            std::fs::write(format!("{output}.annotation"), &workload.annotation)
                .expect("write requested Kata annotation fixture");
            std::fs::write(format!("{output}.ephemeral.toml"), &ephemeral.raw)
                .expect("write requested ephemeral fixture");
            std::fs::write(
                format!("{output}.ephemeral.annotation"),
                &ephemeral.annotation,
            )
            .expect("write requested ephemeral Kata annotation fixture");
            std::fs::write(format!("{output}.supervisor.toml"), &supervisor.raw)
                .expect("write requested supervisor fixture");
            std::fs::write(
                format!("{output}.supervisor.annotation"),
                &supervisor.annotation,
            )
            .expect("write requested supervisor Kata annotation fixture");
        }
        std::fs::remove_dir_all(&temp).expect("remove test directory");
    }
}
