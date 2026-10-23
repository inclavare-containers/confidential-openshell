//! Passive, display-only appraisal records. Never requests quotes or resources.

use jsonwebtoken::{Algorithm, DecodingKey, Validation};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs,
    io::{Read, Write},
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};
use tokio::sync::RwLock;
use tonic::{Request, Response, Status};

#[allow(clippy::all, clippy::pedantic, clippy::nursery, unused_qualifications)]
pub mod proto {
    tonic::include_proto!("kbs.plugin.v1");
}

const MAX_SESSION_BYTES: u64 = 4 * 1024 * 1024;

pub fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

pub fn is_digest(value: &str) -> bool {
    value.len() == 96
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Report {
    pub initdata_sha384: String,
    pub attested_at: u64,
    pub token_expires_at: u64,
    pub observed_at: u64,
    pub ear_sha256: String,
    pub appraisal: String,
    pub policy_id: String,
    pub tee: String,
    pub tcb_status: Option<String>,
    pub trustworthiness: BTreeMap<String, i64>,
    pub measurements: BTreeMap<String, String>,
    /// Newer equivalent attestations advance this watermark without moving ref.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub latest_attested_at: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status_changed_at: Option<u64>,
}

impl Report {
    pub fn conclusive(&self) -> bool {
        matches!(
            self.appraisal.as_str(),
            "affirming" | "warning" | "contraindicated"
        )
    }

    pub fn latest_time(&self) -> u64 {
        self.latest_attested_at.unwrap_or(self.attested_at)
    }

    pub fn status(&self) -> &'static str {
        match self.appraisal.as_str() {
            "affirming" | "warning" => "True",
            "contraindicated" => "False",
            _ => "Unknown",
        }
    }

    pub fn equivalent(&self, other: &Self) -> bool {
        self.initdata_sha384 == other.initdata_sha384
            && self.appraisal == other.appraisal
            && self.policy_id == other.policy_id
            && self.tee == other.tee
            && self.tcb_status == other.tcb_status
            && self.trustworthiness == other.trustworthiness
            && self.measurements == other.measurements
    }
}

/// Keep a representative signed record, plus a watermark to reject late evidence.
/// Persisting these fields also keeps ref and transition time stable after restart.
pub fn merge_report(previous: Option<&Report>, mut incoming: Report) -> Option<Report> {
    if !incoming.conclusive() {
        return None;
    }
    let latest = incoming.latest_time();
    if let Some(old) = previous.filter(|r| r.conclusive()) {
        if latest <= old.latest_time() {
            return None;
        }
        // A driver may miss an intermediate True -> False -> True transition.
        // An already-reduced observer report carries the durable status time;
        // do not merge it as if it were just one raw reattestation.
        if incoming.status_changed_at.is_some() {
            return Some(incoming);
        }
        if old.equivalent(&incoming) {
            let mut retained = old.clone();
            retained.latest_attested_at = Some(latest);
            retained.status_changed_at = Some(old.status_changed_at.unwrap_or(old.attested_at));
            return Some(retained);
        }
        if old.status() == incoming.status() {
            incoming.status_changed_at = Some(old.status_changed_at.unwrap_or(old.attested_at));
        }
    }
    incoming.latest_attested_at = Some(latest);
    incoming
        .status_changed_at
        .get_or_insert(incoming.attested_at);
    Some(incoming)
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Collection {
    pub available: bool,
    pub last_scan_at: Option<u64>,
    pub ignored_records: usize,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Observation {
    pub schema: u32,
    pub collection: Collection,
    pub report: Option<Report>,
}

fn bounded_text(value: Option<&Value>) -> Option<String> {
    value
        .and_then(Value::as_str)
        .filter(|s| s.len() <= 256 && !s.chars().any(char::is_control))
        .map(str::to_owned)
}

/// Signature verification authenticates historical data, not a current credential.
/// In particular, an expired EAR remains useful as a dated observation.
pub fn summarize(token: &str, key: &DecodingKey, observed_at: u64) -> Result<Report, &'static str> {
    let mut validation = Validation::new(Algorithm::ES256);
    validation.validate_exp = false;
    validation.validate_aud = false;
    validation.required_spec_claims.clear();
    let claims = jsonwebtoken::decode::<Value>(token, key, &validation)
        .map_err(|_| "invalid EAR signature")?
        .claims;
    let attested_at = claims["iat"].as_u64().ok_or("missing EAR time")?;
    let token_expires_at = claims["exp"].as_u64().ok_or("missing EAR expiry")?;
    if attested_at > observed_at.saturating_add(60) || token_expires_at <= attested_at {
        return Err("invalid EAR time");
    }
    let cpu = &claims["submods"]["cpu0"];
    let appraisal = bounded_text(cpu.get("ear.status")).ok_or("missing appraisal")?;
    if !["affirming", "warning", "contraindicated", "none"].contains(&appraisal.as_str()) {
        return Err("unknown EAR appraisal");
    }
    let policy_id = bounded_text(cpu.get("ear.appraisal-policy-id")).ok_or("missing policy id")?;
    let evidence = &cpu["ear.veraison.annotated-evidence"]["tdx"];
    let events = evidence["uefi_event_logs"]
        .as_array()
        .ok_or("missing event log")?;
    let initdata = events
        .iter()
        .filter(|e| {
            e["type_name"] == "EV_EVENT_TAG"
                && e["details"]["unicode_name"] == "AAEL"
                && e["details"]["data"]["operation"] == "initdata"
        })
        .collect::<Vec<_>>();
    if initdata.len() != 1
        || initdata[0]["details"]["data"]["domain"] != "confidentialcontainers.org"
    {
        return Err("ambiguous initdata");
    }
    let digest = initdata[0]["details"]["data"]["content"]
        .as_str()
        .filter(|s| is_digest(s))
        .ok_or("invalid initdata digest")?
        .to_owned();
    let measurements = ["mr_td", "rtmr_0", "rtmr_1", "rtmr_2", "rtmr_3"]
        .into_iter()
        .filter_map(|name| {
            evidence["quote"]["body"][name]
                .as_str()
                .filter(|s| is_digest(s))
                .map(|v| (name.to_owned(), v.to_owned()))
        })
        .collect();
    let vector = &cpu["ear.trustworthiness-vector"];
    let trustworthiness = ["hardware", "executables", "configuration", "file-system"]
        .into_iter()
        .filter_map(|name| vector[name].as_i64().map(|v| (name.to_owned(), v)))
        .collect();
    Ok(Report {
        initdata_sha384: digest,
        attested_at,
        token_expires_at,
        observed_at,
        ear_sha256: hex::encode(Sha256::digest(token.as_bytes())),
        appraisal,
        policy_id,
        tee: "tdx".to_owned(),
        tcb_status: bounded_text(evidence.get("tcb_status")),
        trustworthiness,
        measurements,
        latest_attested_at: None,
        status_changed_at: None,
    })
}

fn read_bounded(path: &Path) -> std::io::Result<Vec<u8>> {
    let file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(0o400_000)
        .open(path)?;
    if !file.metadata()?.is_file() {
        return Err(std::io::Error::other("not a regular record"));
    }
    let mut bytes = Vec::new();
    file.take(MAX_SESSION_BYTES + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_SESSION_BYTES {
        return Err(std::io::Error::other("record too large"));
    }
    Ok(bytes)
}

#[derive(Default)]
struct State {
    reports: BTreeMap<String, Report>,
    collection: Collection,
}

#[derive(Clone)]
pub struct Observer {
    sessions: PathBuf,
    output: PathBuf,
    key: KeySource,
    state: Arc<RwLock<State>>,
}

#[derive(Clone)]
enum KeySource {
    Static(DecodingKey),
    File(PathBuf),
}

impl Observer {
    pub fn new(
        sessions: PathBuf,
        output: PathBuf,
        public_key: &[u8],
    ) -> Result<Self, Box<dyn std::error::Error>> {
        Self::open(
            sessions,
            output,
            KeySource::Static(DecodingKey::from_ec_pem(public_key)?),
        )
    }

    /// Key/configuration failures degrade collection without taking down the plugin.
    pub fn with_key_file(
        sessions: PathBuf,
        output: PathBuf,
        public_key: PathBuf,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        Self::open(sessions, output, KeySource::File(public_key))
    }

    fn open(
        sessions: PathBuf,
        output: PathBuf,
        key: KeySource,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        fs::create_dir_all(&output)?;
        fs::set_permissions(&output, fs::Permissions::from_mode(0o700))?;
        fs::create_dir_all(output.join("by-ref"))?;
        fs::set_permissions(output.join("by-ref"), fs::Permissions::from_mode(0o700))?;
        let mut state = State::default();
        // Only our reduced reports are persisted, never bearer tokens or cookies.
        for entry in fs::read_dir(&output)?.flatten() {
            let path = entry.path();
            let Some(digest) = path
                .file_stem()
                .and_then(|v| v.to_str())
                .filter(|v| is_digest(v))
            else {
                continue;
            };
            if let Ok(report) = read_bounded(&path)
                .and_then(|v| serde_json::from_slice::<Report>(&v).map_err(std::io::Error::other))
                && report.initdata_sha384 == digest
                && report.conclusive()
            {
                state.reports.insert(digest.to_owned(), report);
            }
        }
        Ok(Self {
            sessions,
            output,
            key,
            state: Arc::new(RwLock::new(state)),
        })
    }

    /// KBS 0.22 writes sessions in place; partial reads are ignored and retried.
    pub async fn scan(&self) {
        let sessions = self.sessions.clone();
        let key = self.key.clone();
        let scanned_at = now();
        let scanned =
            tokio::task::spawn_blocking(move || -> std::io::Result<(Vec<Report>, usize)> {
                let key = match key {
                    KeySource::Static(key) => key,
                    KeySource::File(path) => DecodingKey::from_ec_pem(&read_bounded(&path)?)
                        .map_err(std::io::Error::other)?,
                };
                let mut reports = Vec::new();
                let mut ignored = 0;
                for entry in fs::read_dir(sessions)? {
                    let entry = entry?;
                    if !entry.file_type()?.is_file() {
                        continue;
                    }
                    let parsed = read_bounded(&entry.path())
                        .ok()
                        .and_then(|v| serde_json::from_slice::<Value>(&v).ok());
                    match parsed {
                        Some(value) if value.get("Authed").is_some() => {}
                        Some(value) => match value
                            .pointer("/Attested/token")
                            .and_then(Value::as_str)
                            .and_then(|t| summarize(t, &key, scanned_at).ok())
                        {
                            Some(report) => reports.push(report),
                            None => ignored += 1,
                        },
                        None => ignored += 1,
                    }
                }
                Ok((reports, ignored))
            })
            .await;
        let Ok(Ok((reports, ignored_records))) = scanned else {
            self.state.write().await.collection.available = false;
            return;
        };
        let mut state = self.state.write().await;
        state.collection = Collection {
            available: true,
            last_scan_at: Some(scanned_at),
            ignored_records,
        };
        // Stable ordering matters when several sessions for one digest arrive together.
        let mut reports = reports;
        reports.sort_by_key(|r| r.attested_at);
        for report in reports {
            let previous = state.reports.get(&report.initdata_sha384);
            let Some(report) = merge_report(previous, report) else {
                continue;
            };
            let saved = (|| -> std::io::Result<()> {
                // Archive semantic transitions, not every token renewal. Old displayed
                // refs remain searchable even while a driver has not polled the update.
                for archived in previous.into_iter().chain(std::iter::once(&report)) {
                    if archived.ear_sha256.len() != 64
                        || !archived.ear_sha256.bytes().all(|b| b.is_ascii_hexdigit())
                    {
                        return Err(std::io::Error::other("invalid record fingerprint"));
                    }
                    let path = self
                        .output
                        .join("by-ref")
                        .join(format!("{}.json", archived.ear_sha256));
                    if !path.exists() {
                        persist_report(&path, archived)?;
                    }
                }
                persist_report(
                    &self.output.join(format!("{}.json", report.initdata_sha384)),
                    &report,
                )
            })();
            if saved.is_err() {
                state.collection.available = false;
                continue;
            }
            state.reports.insert(report.initdata_sha384.clone(), report);
        }
    }

    pub async fn observation(&self, digest: &str) -> Observation {
        let state = self.state.read().await;
        let mut collection = state.collection.clone();
        // The endpoint can be healthy while its scanner is stalled. Clients consume
        // this explicit health result instead of ticking public conditions themselves.
        collection.available &= collection
            .last_scan_at
            .is_some_and(|t| now().saturating_sub(t) <= 30);
        Observation {
            schema: 1,
            collection,
            report: state.reports.get(digest).cloned(),
        }
    }
}

fn persist_report(path: &Path, report: &Report) -> std::io::Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| std::io::Error::other("missing parent"))?;
    let mut tmp = tempfile::NamedTempFile::new_in(parent)?;
    serde_json::to_writer(&mut tmp, report)?;
    tmp.flush()?;
    tmp.as_file().sync_all()?;
    tmp.persist(path).map_err(std::io::Error::other)?;
    fs::File::open(parent)?.sync_all()
}

#[tonic::async_trait]
impl proto::kbs_plugin_server::KbsPlugin for Observer {
    async fn validate_auth(
        &self,
        _: Request<proto::ValidateAuthRequest>,
    ) -> Result<Response<proto::ValidateAuthResponse>, Status> {
        Ok(Response::new(proto::ValidateAuthResponse {
            requires_admin_auth: true,
        }))
    }
    async fn needs_encryption(
        &self,
        _: Request<proto::NeedsEncryptionRequest>,
    ) -> Result<Response<proto::NeedsEncryptionResponse>, Status> {
        Ok(Response::new(proto::NeedsEncryptionResponse {
            requires_payload_encryption: false,
        }))
    }
    async fn handle(
        &self,
        request: Request<proto::PluginRequest>,
    ) -> Result<Response<proto::PluginResponse>, Status> {
        let req = request.into_inner();
        if req.method != "GET"
            || req.path.len() != 1
            || !is_digest(&req.path[0])
            || !req.body.is_empty()
            || !req.query.is_empty()
        {
            return Err(Status::invalid_argument("expected GET /<initdata-sha384>"));
        }
        let body = serde_json::to_vec(&self.observation(&req.path[0]).await)
            .map_err(|_| Status::internal("report encoding failed"))?;
        Ok(Response::new(proto::PluginResponse {
            body,
            status_code: 200,
            content_type: "application/json".into(),
        }))
    }
}
