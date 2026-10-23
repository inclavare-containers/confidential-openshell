//! Optional history display. This module never supplies lifecycle or authorization inputs.
use crate::bootstrap::Binding;
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use openshell_attestation_observer::{Collection, Observation, Report, is_digest, now};
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

pub const TYPES: [&str; 2] = ["SupervisorAttested", "WorkloadAttested"];
// Strip both generations from cloud snapshots, including when display is off.
pub const RESERVED_TYPES: [&str; 4] = [
    TYPES[0],
    TYPES[1],
    "SupervisorAttestation",
    "WorkloadAttestation",
];
const REFRESH: Duration = Duration::from_secs(10);
const MAX_ENTRIES: usize = 1024;

#[derive(Default)]
struct Entry {
    started: Option<Instant>,
    fetching: bool,
    collection: Option<Collection>,
    report: Option<Report>,
    error: Option<&'static str>,
}

impl Entry {
    fn observe(&mut self, observation: Observation) {
        self.collection = Some(observation.collection);
        self.error = None;
        // Attested describes a completed event for this attempt. A missed scan,
        // expired session or unspecified appraisal cannot undo that event.
        if let Some(report) = observation.report
            && matches!(
                report.appraisal.as_str(),
                "affirming" | "warning" | "contraindicated"
            )
            && self
                .report
                .as_ref()
                .is_none_or(|old| report.attested_at > old.attested_at)
        {
            self.report = Some(report);
        }
    }
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
        bindings: Option<&[Binding]>,
        should_run: bool,
    ) -> Vec<SandboxCondition> {
        let mut conditions = Vec::new();
        for (role, kind) in ["supervisor", "workload"].into_iter().zip(TYPES) {
            if !should_run {
                conditions.push(condition(kind, "Unknown", "NotRunning", "no running guest"));
                continue;
            }
            let Some(bindings) = bindings else {
                conditions.push(unavailable(kind, "cannot read the current guest binding"));
                continue;
            };
            let binding = bindings
                .iter()
                .find(|b| b.role == role && is_digest(&b.initdata_sha384));
            let Some(binding) = binding else {
                conditions.push(pending(kind));
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
                            Ok(Ok(observation)) => entry.observe(observation),
                            _ => entry.error = Some("ReportQueryUnavailable"),
                        }
                        drop(permit);
                    });
                }
            }
            if let Some(report) = &entry.report {
                conditions.push(attested(kind, report));
                continue;
            }
            let available = entry.error.is_none()
                && entry.collection.as_ref().is_some_and(|collection| {
                    collection.available
                        && collection
                            .last_scan_at
                            .is_some_and(|t| now().saturating_sub(t) <= 30)
                })
                && entry
                    .started
                    .is_some_and(|t| t.elapsed() <= Duration::from_secs(30));
            conditions.push(
                if available || (entry.collection.is_none() && entry.error.is_none()) {
                    pending(kind)
                } else {
                    unavailable(kind, "cannot read Trustee records")
                },
            );
        }
        conditions
    }
}

fn condition(
    kind: &str,
    status: &str,
    reason: &str,
    message: impl Into<String>,
) -> SandboxCondition {
    SandboxCondition {
        r#type: kind.into(),
        status: status.into(),
        reason: reason.into(),
        message: message.into(),
        transition_time: None,
    }
}

fn pending(kind: &str) -> SandboxCondition {
    condition(
        kind,
        "Unknown",
        "AttestationPending",
        "waiting for the guest to attest to Trustee",
    )
}

fn unavailable(kind: &str, message: &str) -> SandboxCondition {
    condition(kind, "Unknown", "AttestationStatusUnavailable", message)
}

fn attested(kind: &str, report: &Report) -> SandboxCondition {
    // A reference to the signed appraisal record, not an image/reference-value hash.
    let reference: String = report.ear_sha256.chars().take(8).collect();
    if report.appraisal == "contraindicated" {
        return condition(
            kind,
            "False",
            "AttestationRejected",
            format!("Trustee rejected the evidence (appraisal: contraindicated) · ref {reference}"),
        );
    }
    let warning = report.appraisal == "warning";
    let tcb = match report.tcb_status.as_deref() {
        Some("UpToDate") => "TCB up to date".to_owned(),
        Some(status) if !warning => format!("TCB {status} (allowed by appraisal policy)"),
        Some(status) => format!("TCB {status}"),
        None => "TCB status unavailable".to_owned(),
    };
    let reason = if warning || report.tcb_status.as_deref() != Some("UpToDate") {
        "AttestedWithWarning"
    } else {
        "Attested"
    };
    let appraisal = if warning {
        " · Trustee appraisal warning"
    } else {
        ""
    };
    condition(
        kind,
        "True",
        reason,
        format!("Intel TDX · verified by Trustee · {tcb}{appraisal} · ref {reference}"),
    )
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
                tcb_status: Some("UpToDate".into()),
                trustworthiness: BTreeMap::default(),
                measurements: BTreeMap::default(),
            }),
        }
    }

    fn entry(observation: Observation) -> Entry {
        let mut entry = Entry {
            started: Some(Instant::now()),
            ..Entry::default()
        };
        entry.observe(observation);
        entry
    }

    #[test]
    fn appraisal_and_tcb_have_distinct_one_line_results() {
        for (appraisal, tcb, status, reason, text) in [
            (
                "affirming",
                Some("UpToDate"),
                "True",
                "Attested",
                "TCB up to date",
            ),
            (
                "affirming",
                Some("OutOfDate"),
                "True",
                "AttestedWithWarning",
                "TCB OutOfDate (allowed by appraisal policy)",
            ),
            (
                "warning",
                Some("UpToDate"),
                "True",
                "AttestedWithWarning",
                "Trustee appraisal warning",
            ),
            (
                "warning",
                Some("OutOfDate"),
                "True",
                "AttestedWithWarning",
                "TCB OutOfDate · Trustee appraisal warning",
            ),
            (
                "affirming",
                None,
                "True",
                "AttestedWithWarning",
                "TCB status unavailable",
            ),
            (
                "contraindicated",
                Some("UpToDate"),
                "False",
                "AttestationRejected",
                "Trustee rejected the evidence",
            ),
        ] {
            let mut report = observation().report.unwrap();
            report.appraisal = appraisal.into();
            report.tcb_status = tcb.map(str::to_owned);
            let condition = attested(TYPES[1], &report);
            assert_eq!(
                (condition.status.as_str(), condition.reason.as_str()),
                (status, reason)
            );
            assert!(condition.message.contains(text), "{}", condition.message);
            assert!(condition.message.ends_with(" · ref bbbbbbbb"));
            assert_eq!(condition.message.lines().count(), 1);
            assert!(!condition.message.contains("boot image not approved"));
            if appraisal == "warning" {
                assert!(!condition.message.contains("allowed by"));
            }
        }
    }

    #[tokio::test]
    async fn history_survives_outages_but_never_crosses_attempts_or_stop() {
        let reports = Reports::new(PathBuf::from("/not-configured"));
        let digest = "a".repeat(96);
        let bindings = [binding(&digest)];
        reports
            .entries
            .lock()
            .await
            .insert(digest.clone(), entry(observation()));
        let original = reports.conditions(Some(&bindings), true).await;
        assert_eq!(original[1].status, "True"); // Expired EAR remains history.
        reports.entries.lock().await.get_mut(&digest).unwrap().error =
            Some("ReportQueryUnavailable");
        assert_eq!(reports.conditions(Some(&bindings), true).await, original);
        let mut entries = reports.entries.lock().await;
        let cached = entries.get_mut(&digest).unwrap();
        cached.error = None;
        cached.collection.as_mut().unwrap().last_scan_at = Some(now() - 60);
        drop(entries);
        assert_eq!(reports.conditions(Some(&bindings), true).await, original);
        for appraisal in [None, Some("none")] {
            let mut fresh = observation();
            if let Some(appraisal) = appraisal {
                fresh.report.as_mut().unwrap().appraisal = appraisal.into();
                fresh.report.as_mut().unwrap().attested_at += 1;
            } else {
                fresh.report = None;
            }
            reports
                .entries
                .lock()
                .await
                .get_mut(&digest)
                .unwrap()
                .observe(fresh);
            assert_eq!(reports.conditions(Some(&bindings), true).await, original);
        }
        // Revoked/absent bindings must not reuse cached reports.
        assert!(
            reports
                .conditions(Some(&[]), true)
                .await
                .iter()
                .all(|c| c.reason == "AttestationPending")
        );
        assert_eq!(
            reports
                .conditions(Some(&[binding(&"c".repeat(96))]), true)
                .await[1]
                .reason,
            "AttestationPending"
        );
        // Even if an old binding is still present during stop, hide its report.
        assert!(
            reports
                .conditions(Some(&bindings), false)
                .await
                .iter()
                .all(|c| c.reason == "NotRunning" && c.message == "no running guest")
        );
        assert!(
            reports
                .conditions(None, true)
                .await
                .iter()
                .all(|c| c.reason == "AttestationStatusUnavailable")
        );
    }

    #[tokio::test]
    async fn pending_and_unavailable_only_apply_before_a_result() {
        let reports = Reports::new(PathBuf::from("/not-configured"));
        let digest = "a".repeat(96);
        let bindings = [binding(&digest)];
        let mut empty = observation();
        empty.report = None;
        reports
            .entries
            .lock()
            .await
            .insert(digest.clone(), entry(empty));
        assert_eq!(
            reports.conditions(Some(&bindings), true).await[1].reason,
            "AttestationPending"
        );
        reports
            .entries
            .lock()
            .await
            .get_mut(&digest)
            .unwrap()
            .collection
            .as_mut()
            .unwrap()
            .last_scan_at = Some(now() - 60);
        assert_eq!(
            reports.conditions(Some(&bindings), true).await[1].reason,
            "AttestationStatusUnavailable"
        );
        reports.entries.lock().await.get_mut(&digest).unwrap().error =
            Some("ReportQueryUnavailable");
        assert_eq!(
            reports.conditions(Some(&bindings), true).await[1].reason,
            "AttestationStatusUnavailable"
        );
        reports
            .entries
            .lock()
            .await
            .get_mut(&digest)
            .unwrap()
            .observe(observation());
        assert_eq!(
            reports.conditions(Some(&bindings), true).await[1].reason,
            "Attested"
        );
    }

    #[test]
    fn newer_explicit_rejection_replaces_success_and_old_records_do_not_replace_it() {
        let mut cached = entry(observation());
        let mut rejected = observation();
        rejected.report.as_mut().unwrap().attested_at += 1;
        rejected.report.as_mut().unwrap().appraisal = "contraindicated".into();
        cached.observe(rejected);
        cached.observe(observation());
        assert_eq!(
            attested(TYPES[1], cached.report.as_ref().unwrap()).status,
            "False"
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
            entries.insert(binding.initdata_sha384.clone(), entry(observation));
        }
        drop(entries);
        let conditions = reports
            .conditions(Some(&[workload, supervisor]), true)
            .await;
        assert_eq!(conditions.len(), 2);
        assert_eq!(conditions[0].r#type, "SupervisorAttested");
        assert_eq!(conditions[0].reason, "Attested");
        assert_eq!(conditions[1].r#type, "WorkloadAttested");
        assert_eq!(conditions[1].status, "True");
        assert_eq!(conditions[1].reason, "AttestedWithWarning");
    }

    #[tokio::test]
    async fn unavailable_configuration_returns_without_waiting_for_query() {
        let reports = Reports::new(PathBuf::from("/not-configured"));
        let conditions = tokio::time::timeout(
            Duration::from_millis(100),
            reports.conditions(Some(&[binding(&"a".repeat(96))]), true),
        )
        .await
        .unwrap();
        assert_eq!(conditions[1].reason, "AttestationPending");
    }

    #[tokio::test]
    #[ignore = "requires the temporary released-KBS fixture from check-attestation-reports.py"]
    async fn released_kbs_attestation_report_query() {
        let config = PathBuf::from(std::env::var("OPENSHELL_TEST_REPORT_CONFIG").unwrap());
        let observation = query(&config, &"a".repeat(96)).await.unwrap();
        assert_eq!(observation.report.as_ref().unwrap().appraisal, "affirming");
        let reports = Reports::new(config);
        reports
            .entries
            .lock()
            .await
            .insert("a".repeat(96), entry(observation));
        let conditions = reports
            .conditions(Some(&[binding(&"a".repeat(96))]), true)
            .await;
        assert_eq!(conditions[1].status, "True");
        // The unchanged compute-driver protocol carries the one-line message.
        let encoded = conditions[1].encode_to_vec();
        if let Ok(path) = std::env::var("OPENSHELL_TEST_REPORT_CONDITION") {
            std::fs::write(path, &encoded).unwrap();
        }
        let decoded = SandboxCondition::decode(encoded.as_slice()).unwrap();
        assert_eq!(decoded.r#type, "WorkloadAttested");
        assert_eq!(decoded.reason, "Attested");
        assert!(
            decoded
                .message
                .starts_with("Intel TDX · verified by Trustee · TCB up to date · ref ")
        );
    }
}
