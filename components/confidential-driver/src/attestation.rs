//! Optional history display. This module never supplies lifecycle or authorization inputs.
use crate::bootstrap::Binding;
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use openshell_attestation_observer::{Observation, is_digest, now};
use openshell_core::proto::compute::v1::DriverCondition as SandboxCondition;
use serde::Deserialize;
use serde_json::json;
use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::sync::{Mutex, Semaphore};

pub const TYPES: [&str; 2] = ["SupervisorAttestation", "WorkloadAttestation"];
const REFRESH: Duration = Duration::from_secs(10);
const MAX_ENTRIES: usize = 1024;

#[derive(Default)]
struct Entry {
    started: Option<Instant>,
    fetching: bool,
    observation: Option<Observation>,
    error: Option<&'static str>,
}

pub struct Reports {
    config: PathBuf,
    entries: Mutex<HashMap<String, Entry>>,
    slots: Arc<Semaphore>,
}

impl Reports {
    pub(super) fn new(config: PathBuf) -> Arc<Self> {
        Arc::new(Self {
            config,
            entries: Mutex::new(HashMap::new()),
            slots: Arc::new(Semaphore::new(8)),
        })
    }

    /// Return immediately with the previous result; network IO runs separately.
    pub(super) async fn conditions(
        self: &Arc<Self>,
        bindings: &[Binding],
    ) -> Vec<SandboxCondition> {
        let mut conditions = Vec::new();
        for (role, kind) in ["supervisor", "workload"].into_iter().zip(TYPES) {
            let binding = bindings
                .iter()
                .find(|b| b.role == role && is_digest(&b.initdata_sha384));
            let Some(binding) = binding else {
                conditions.push(condition(
                    kind,
                    "Unknown",
                    "NoActiveBinding",
                    json!({
                        "schema": 1, "source": "trustee-session-observer", "historical": true,
                        "role": role, "bound_to_current_attempt": false, "report": null
                    }),
                ));
                continue;
            };
            let digest = binding.initdata_sha384.clone();
            let mut entries = self.entries.lock().await;
            if entries.len() >= MAX_ENTRIES
                && !entries.contains_key(&digest)
                && let Some(oldest) = entries
                    .iter()
                    .filter(|(_, e)| !e.fetching)
                    .min_by_key(|(_, e)| e.started)
                    .map(|(k, _)| k.clone())
            {
                entries.remove(&oldest);
            }
            let entry = entries.entry(digest.clone()).or_default();
            if !entry.fetching && entry.started.is_none_or(|t| t.elapsed() >= REFRESH) {
                // No queued tasks: a full pool is retried on the next snapshot.
                if let Ok(permit) = self.slots.clone().try_acquire_owned() {
                    entry.fetching = true;
                    entry.started = Some(Instant::now());
                    let this = self.clone();
                    tokio::spawn(async move {
                        let result = tokio::time::timeout(
                            Duration::from_secs(3),
                            query(&this.config, &digest),
                        )
                        .await;
                        let mut entries = this.entries.lock().await;
                        let entry = entries.entry(digest).or_default();
                        entry.fetching = false;
                        match result {
                            Ok(Ok(observation)) => {
                                entry.observation = Some(observation);
                                entry.error = None;
                            }
                            _ => entry.error = Some("ReportQueryUnavailable"),
                        }
                        drop(permit);
                    });
                }
            }
            let observation = entry.observation.as_ref();
            let report = observation.and_then(|o| o.report.as_ref());
            let available = entry.error.is_none()
                && observation.is_some_and(|o| {
                    o.collection.available
                        && o.collection
                            .last_scan_at
                            .is_some_and(|t| now().saturating_sub(t) <= 30)
                })
                && entry
                    .started
                    .is_some_and(|t| t.elapsed() <= Duration::from_secs(30));
            let (status, reason) = if available {
                match report.map(|r| r.appraisal.as_str()) {
                    Some("affirming") => ("True", "HistoricalAppraisalAffirming"),
                    Some("warning" | "contraindicated") => {
                        ("False", "HistoricalAppraisalNotAffirming")
                    }
                    Some(_) => ("Unknown", "HistoricalAppraisalUnspecified"),
                    None => ("Unknown", "NotObserved"),
                }
            } else {
                ("Unknown", "CollectionUnavailable")
            };
            conditions.push(condition(kind, status, reason, json!({
                "schema": 1, "source": "trustee-session-observer", "historical": true,
                "bound_to_current_attempt": true, "role": role,
                "sandbox_cr_uid": binding.sandbox_cr_uid, "generation": binding.generation,
                "attempt": binding.attempt_id, "initdata_sha384": binding.initdata_sha384,
                "query_error": entry.error, "collection": observation.map(|o| &o.collection), "report": report,
            })));
        }
        conditions
    }
}

fn condition(
    kind: &str,
    status: &str,
    reason: &str,
    message: serde_json::Value,
) -> SandboxCondition {
    SandboxCondition {
        r#type: kind.into(),
        status: status.into(),
        reason: reason.into(),
        message: message.to_string(),
        transition_time: None,
    }
}

#[derive(Deserialize)]
struct Config {
    kbs_url: String,
    ca_cert: PathBuf,
    admin_key: PathBuf,
}

async fn query(config: &Path, digest: &str) -> Result<Observation, &'static str> {
    if !is_digest(digest) {
        return Err("invalid digest");
    }
    let settings: Config = serde_json::from_slice(
        &tokio::fs::read(config)
            .await
            .map_err(|_| "configuration unavailable")?,
    )
    .map_err(|_| "invalid configuration")?;
    let mut url = reqwest::Url::parse(&settings.kbs_url).map_err(|_| "invalid origin")?;
    if url.scheme() != "https"
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.path() != "/"
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err("expected HTTPS origin");
    }
    url.set_path(&format!("/kbs/v0/external/attestation-reports/{digest}"));
    let ca = tokio::fs::read(settings.ca_cert)
        .await
        .map_err(|_| "CA unavailable")?;
    let key = tokio::fs::read(settings.admin_key)
        .await
        .map_err(|_| "admin identity unavailable")?;
    let timestamp = now();
    let jwt = jsonwebtoken::encode(&Header::new(Algorithm::ES256), &json!({
        "iss": "confidential-openshell-driver", "aud": "kbs-admin", "role": "confidential-openshell",
        "nbf": timestamp.saturating_sub(10), "exp": timestamp + 60
    }), &EncodingKey::from_ec_pem(&key).map_err(|_| "invalid admin identity")?).map_err(|_| "signing failed")?;
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let client = reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .tls_built_in_root_certs(false)
        .add_root_certificate(reqwest::Certificate::from_pem(&ca).map_err(|_| "invalid CA")?)
        .timeout(Duration::from_secs(2))
        .build()
        .map_err(|_| "client unavailable")?;
    let mut response = client
        .get(url)
        .bearer_auth(jwt)
        .send()
        .await
        .map_err(|_| "query unavailable")?;
    if response.status() != reqwest::StatusCode::OK {
        return Err("query rejected");
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|_| "response unavailable")? {
        if bytes.len() + chunk.len() > 65536 {
            return Err("oversized response");
        }
        bytes.extend_from_slice(&chunk);
    }
    let observation: Observation =
        serde_json::from_slice(&bytes).map_err(|_| "invalid response")?;
    if observation.schema != 1
        || observation
            .report
            .as_ref()
            .is_some_and(|r| r.initdata_sha384 != digest)
    {
        return Err("mismatched response");
    }
    Ok(observation)
}

#[cfg(test)]
mod tests {
    use super::*;
    use openshell_attestation_observer::{Collection, Report};
    use prost::Message;
    use std::collections::BTreeMap;

    fn binding(digest: &str) -> Binding {
        Binding {
            resource_path: String::new(),
            initdata_sha384: digest.into(),
            role: "workload".into(),
            generation: "generation".into(),
            sandbox_id: "sandbox".into(),
            sandbox_cr_uid: "uid".into(),
            attempt_id: "attempt".into(),
            key: String::new(),
            resource_sha256: String::new(),
            identity_sha256: String::new(),
        }
    }
    fn observation() -> Observation {
        Observation {
            schema: 1,
            collection: Collection {
                available: true,
                last_scan_at: Some(now()),
                ignored_records: 0,
            },
            report: Some(Report {
                initdata_sha384: "a".repeat(96),
                attested_at: now() - 600,
                token_expires_at: now() - 300,
                observed_at: now(),
                ear_sha256: "b".repeat(64),
                appraisal: "affirming".into(),
                policy_id: "default".into(),
                tee: "tdx".into(),
                tcb_status: None,
                trustworthiness: BTreeMap::default(),
                measurements: BTreeMap::default(),
            }),
        }
    }

    #[tokio::test]
    async fn history_is_scoped_to_current_binding_and_outages_are_unknown() {
        let reports = Reports::new(PathBuf::from("/not-configured"));
        let digest = "a".repeat(96);
        reports.entries.lock().await.insert(
            digest.clone(),
            Entry {
                started: Some(Instant::now()),
                fetching: false,
                observation: Some(observation()),
                error: None,
            },
        );
        let conditions = reports.conditions(&[binding(&digest)]).await;
        assert_eq!(conditions[1].status, "True");
        let message: serde_json::Value = serde_json::from_str(&conditions[1].message).unwrap();
        assert_eq!(message["historical"], true);
        assert_eq!(message["sandbox_cr_uid"], "uid");
        // Stop/revoke removes active bindings; a prior result cannot remain current.
        assert!(
            reports
                .conditions(&[])
                .await
                .iter()
                .all(|c| c.status == "Unknown")
        );
        assert_eq!(
            reports.conditions(&[binding(&"c".repeat(96))]).await[1].status,
            "Unknown"
        );
        reports.entries.lock().await.get_mut(&digest).unwrap().error =
            Some("ReportQueryUnavailable");
        let conditions = reports.conditions(&[binding(&digest)]).await;
        assert_eq!(conditions[1].status, "Unknown");
        assert!(conditions[1].message.contains("affirming")); // Explicitly retained historical data.
        let mut entries = reports.entries.lock().await;
        let entry = entries.get_mut(&digest).unwrap();
        entry.error = None;
        entry.observation.as_mut().unwrap().collection.last_scan_at = Some(now() - 60);
        drop(entries);
        assert_eq!(
            reports.conditions(&[binding(&digest)]).await[1].status,
            "Unknown"
        );
    }

    #[tokio::test]
    async fn role_appraisals_are_independent() {
        let reports = Reports::new(PathBuf::from("/not-configured"));
        let mut supervisor = binding(&"d".repeat(96));
        supervisor.role = "supervisor".into();
        let workload = binding(&"a".repeat(96));
        let mut entries = reports.entries.lock().await;
        for binding in [&supervisor, &workload] {
            let mut observation = observation();
            let report = observation.report.as_mut().unwrap();
            report.initdata_sha384.clone_from(&binding.initdata_sha384);
            if binding.role == "workload" {
                report.appraisal = "warning".into();
            }
            entries.insert(
                binding.initdata_sha384.clone(),
                Entry {
                    started: Some(Instant::now()),
                    fetching: false,
                    observation: Some(observation),
                    error: None,
                },
            );
        }
        drop(entries);
        let conditions = reports.conditions(&[workload, supervisor]).await;
        assert_eq!(conditions[0].r#type, "SupervisorAttestation");
        assert_eq!(conditions[0].status, "True");
        assert_eq!(conditions[1].r#type, "WorkloadAttestation");
        assert_eq!(conditions[1].status, "False");
        assert_eq!(conditions[1].reason, "HistoricalAppraisalNotAffirming");
    }

    #[tokio::test]
    async fn unavailable_configuration_returns_without_waiting_for_query() {
        let reports = Reports::new(PathBuf::from("/not-configured"));
        let conditions = tokio::time::timeout(
            Duration::from_millis(100),
            reports.conditions(&[binding(&"a".repeat(96))]),
        )
        .await
        .unwrap();
        assert_eq!(conditions[1].status, "Unknown");
    }

    #[tokio::test]
    #[ignore = "requires the temporary released-KBS fixture from check-attestation-reports.py"]
    async fn released_kbs_attestation_report_query() {
        let config = PathBuf::from(std::env::var("OPENSHELL_TEST_REPORT_CONFIG").unwrap());
        let observation = query(&config, &"a".repeat(96)).await.unwrap();
        assert_eq!(observation.report.as_ref().unwrap().appraisal, "affirming");
        let reports = Reports::new(config);
        reports.entries.lock().await.insert(
            "a".repeat(96),
            Entry {
                started: Some(Instant::now()),
                fetching: false,
                observation: Some(observation),
                error: None,
            },
        );
        let conditions = reports.conditions(&[binding(&"a".repeat(96))]).await;
        assert_eq!(conditions[1].status, "True");
        // The unchanged compute-driver protocol carries the JSON string.
        let encoded = conditions[1].encode_to_vec();
        if let Ok(path) = std::env::var("OPENSHELL_TEST_REPORT_CONDITION") {
            std::fs::write(path, &encoded).unwrap();
        }
        let decoded = SandboxCondition::decode(encoded.as_slice()).unwrap();
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&decoded.message).unwrap()["report"]["tee"],
            "tdx"
        );
    }
}
