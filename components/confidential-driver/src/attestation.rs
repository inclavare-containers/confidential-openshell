//! Optional history display. Never supplies lifecycle or authorization inputs.
mod client;

use crate::bootstrap::Binding;
use openshell_attestation_observer::{Observation, Report, is_digest, merge_report, now};
use openshell_core::proto::compute::v1::DriverCondition as SandboxCondition;
use std::{
    collections::HashMap,
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};
use tokio::{
    sync::{Mutex, Notify, Semaphore, broadcast},
    time::Instant,
};

pub const TYPES: [&str; 2] = ["SupervisorAttested", "WorkloadAttested"];
pub const RESERVED_TYPES: [&str; 4] = [
    TYPES[0],
    TYPES[1],
    "SupervisorAttestation",
    "WorkloadAttestation",
];
const PENDING_WINDOW: Duration = Duration::from_mins(5);
const PENDING_REFRESH: Duration = Duration::from_secs(5);
const SETTLED_REFRESH: Duration = Duration::from_mins(1);
const VIEW_LEASE: Duration = Duration::from_mins(10);
const MAX_ENTRIES: usize = 1024;

#[derive(Clone, PartialEq, Eq)]
struct Identity {
    generation: String,
    attempt: String,
    digest: String,
}

struct Entry {
    identity: Option<Identity>,
    first_seen: Instant,
    next_query: Instant,
    job: Option<u64>,
    report: Option<Report>,
    unavailable: bool,
    condition: SandboxCondition,
}

impl Entry {
    fn new(kind: &str, identity: Option<Identity>) -> Self {
        Self {
            identity,
            first_seen: Instant::now(),
            next_query: Instant::now(),
            job: None,
            report: None,
            unavailable: false,
            condition: pending(kind),
        }
    }

    fn refresh(&mut self, kind: &str, running: bool, binding_known: bool) -> bool {
        let mut next = if !running {
            condition(kind, "Unknown", "NotRunning", "no running guest")
        } else if !binding_known {
            unavailable(kind, "cannot read the current guest binding")
        } else if let Some(report) = &self.report {
            attested(kind, report)
        } else if self.unavailable {
            unavailable(kind, "cannot read Trustee records")
        } else if self.first_seen.elapsed() >= PENDING_WINDOW {
            unavailable(kind, "no Trustee record captured for this attempt")
        } else {
            pending(kind)
        };
        // Known results carry the observer's durable status time. For Unknown,
        // changing a reason (pending/unavailable) is not a status transition.
        if next.status == "Unknown" && next.status == self.condition.status {
            next.transition_time = self.condition.transition_time;
        }
        let changed = next != self.condition;
        self.condition = next;
        changed
    }

    fn observe(&mut self, observation: Observation) {
        self.unavailable = !observation.collection.available;
        if let Some(incoming) = observation.report
            && let Some(report) = merge_report(self.report.as_ref(), incoming)
        {
            self.report = Some(report);
        }
    }

    fn retry_after(&self) -> Duration {
        if self.report.is_none() && self.first_seen.elapsed() < PENDING_WINDOW {
            PENDING_REFRESH + Duration::from_millis(u64::from(rand::random::<u16>()) % 1000)
        } else {
            SETTLED_REFRESH + Duration::from_secs(u64::from(rand::random::<u8>()) % 16)
        }
    }
}

struct View {
    uid: String,
    running: bool,
    binding_known: bool,
    last_seen: Instant,
    roles: [Entry; 2],
}

impl View {
    fn new(uid: &str) -> Self {
        Self {
            uid: uid.into(),
            running: true,
            binding_known: true,
            last_seen: Instant::now(),
            roles: std::array::from_fn(|i| Entry::new(TYPES[i], None)),
        }
    }
}

pub struct Reports {
    client: client::Client,
    views: Mutex<HashMap<String, View>>,
    slots: Arc<Semaphore>,
    sequence: AtomicU64,
    changes: broadcast::Sender<String>,
    wake: Arc<Notify>,
}

impl Reports {
    fn build(config: PathBuf) -> Arc<Self> {
        Arc::new(Self {
            client: client::Client::new(config),
            views: Mutex::default(),
            slots: Arc::new(Semaphore::new(8)),
            sequence: AtomicU64::new(1),
            changes: broadcast::channel(256).0,
            wake: Arc::new(Notify::new()),
        })
    }

    pub(super) fn new(config: PathBuf) -> Arc<Self> {
        let reports = Self::build(config);
        let weak = Arc::downgrade(&reports);
        let wake = reports.wake.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(Duration::from_secs(1));
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                tokio::select! { _ = tick.tick() => {}, () = wake.notified() => {} }
                let Some(reports) = weak.upgrade() else {
                    return;
                };
                reports.poll_due().await;
            }
        });
        reports
    }

    pub(super) fn subscribe(&self) -> broadcast::Receiver<String> {
        self.changes.subscribe()
    }

    pub(super) async fn forget(&self, sandbox_id: &str) {
        self.views.lock().await.remove(sandbox_id);
    }

    /// Register only trusted bindings. Network IO and retries run independently
    /// of Get/List/watch; unchanged query results emit no watch notification.
    pub(super) async fn conditions(
        &self,
        sandbox_id: &str,
        uid: &str,
        bindings: Option<&[Binding]>,
        should_run: bool,
    ) -> Vec<SandboxCondition> {
        let mut views = self.views.lock().await;
        if !views.contains_key(sandbox_id)
            && views.len() >= MAX_ENTRIES
            && let Some(oldest) = views
                .iter()
                .min_by_key(|(_, v)| v.last_seen)
                .map(|(id, _)| id.clone())
        {
            views.remove(&oldest);
        }
        let view = views
            .entry(sandbox_id.into())
            .or_insert_with(|| View::new(uid));
        if view.uid != uid {
            *view = View::new(uid);
        }
        view.last_seen = Instant::now();
        if view.running != should_run {
            view.roles = std::array::from_fn(|i| Entry::new(TYPES[i], None));
        }
        view.running = should_run;
        view.binding_known = bindings.is_some();
        for (i, role) in ["supervisor", "workload"].into_iter().enumerate() {
            let entry = &mut view.roles[i];
            if !should_run {
                if entry.identity.is_some() {
                    *entry = Entry::new(TYPES[i], None);
                }
            } else if let Some(bindings) = bindings {
                let identity = bindings
                    .iter()
                    .find(|b| {
                        b.role == role
                            && b.sandbox_id == sandbox_id
                            && b.sandbox_cr_uid == uid
                            && is_digest(&b.initdata_sha384)
                    })
                    .map(|b| Identity {
                        generation: b.generation.clone(),
                        attempt: b.attempt_id.clone(),
                        digest: b.initdata_sha384.clone(),
                    });
                if entry.identity != identity {
                    *entry = Entry::new(TYPES[i], identity);
                }
            } else {
                // Retain history for recovery, but do not assert that it belongs to
                // the current run until the trusted binding can be read again.
                entry.job = None;
            }
            entry.refresh(TYPES[i], view.running, view.binding_known);
        }
        let result = view.roles.iter().map(|e| e.condition.clone()).collect();
        drop(views);
        self.wake.notify_one();
        result
    }

    async fn poll_due(self: &Arc<Self>) {
        let mut views = self.views.lock().await;
        views.retain(|_, v| v.last_seen.elapsed() < VIEW_LEASE);
        for (id, view) in views.iter_mut() {
            if !view.running || !view.binding_known {
                continue;
            }
            let mut changed = false;
            for (i, entry) in view.roles.iter_mut().enumerate() {
                changed |= entry.refresh(TYPES[i], true, true);
                let Some(identity) = entry.identity.as_ref() else {
                    continue;
                };
                if entry.job.is_some() || Instant::now() < entry.next_query {
                    continue;
                }
                let Ok(permit) = self.slots.clone().try_acquire_owned() else {
                    continue;
                };
                let job = self.sequence.fetch_add(1, Ordering::Relaxed);
                entry.job = Some(job);
                let (id, uid, digest) = (id.clone(), view.uid.clone(), identity.digest.clone());
                let reports = self.clone();
                tokio::spawn(async move {
                    let result =
                        tokio::time::timeout(Duration::from_secs(3), reports.client.query(&digest))
                            .await
                            .unwrap_or(Err("query timed out"));
                    reports.complete(&id, &uid, i, job, result).await;
                    drop(permit);
                });
            }
            if changed {
                let _ = self.changes.send(id.clone());
            }
        }
    }

    async fn complete(
        &self,
        id: &str,
        uid: &str,
        role: usize,
        job: u64,
        result: Result<Observation, &'static str>,
    ) {
        let mut views = self.views.lock().await;
        let Some(view) = views.get_mut(id) else {
            return;
        };
        if view.uid != uid || !view.running || !view.binding_known {
            return;
        }
        let entry = &mut view.roles[role];
        if entry.job != Some(job) {
            return;
        }
        entry.job = None;
        match result {
            Ok(observation) => entry.observe(observation),
            Err(_) => entry.unavailable = true,
        }
        entry.next_query = Instant::now() + entry.retry_after();
        if entry.refresh(TYPES[role], true, true) {
            let _ = self.changes.send(id.into());
        }
    }
}

fn timestamp(seconds: u64) -> Option<prost_types::Timestamp> {
    // Protobuf Timestamp is limited to years 0001..9999.
    (seconds <= 253_402_300_799).then_some(prost_types::Timestamp {
        seconds: i64::try_from(seconds).ok()?,
        nanos: 0,
    })
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
        transition_time: timestamp(now()),
    }
}

fn pending(kind: &str) -> SandboxCondition {
    condition(
        kind,
        "Unknown",
        "AttestationPending",
        "waiting for a Trustee record for this attempt",
    )
}

fn unavailable(kind: &str, message: &str) -> SandboxCondition {
    condition(kind, "Unknown", "AttestationStatusUnavailable", message)
}

fn attested(kind: &str, report: &Report) -> SandboxCondition {
    let reference: String = report.ear_sha256.chars().take(8).collect();
    let mut result = if report.appraisal == "contraindicated" {
        condition(
            kind,
            "False",
            "AttestationRejected",
            format!("Trustee rejected the evidence (appraisal: contraindicated) · ref {reference}"),
        )
    } else {
        let warning = report.appraisal == "warning";
        let tcb = match report.tcb_status.as_deref() {
            Some("UpToDate") => "up to date",
            Some("OutOfDate") => "out of date",
            Some("ConfigurationNeeded") => "configuration needed",
            Some("SWHardeningNeeded") => "SW hardening needed",
            Some("ConfigurationAndSWHardeningNeeded") => "configuration and SW hardening needed",
            Some("OutOfDateConfigurationNeeded") => "out of date, configuration needed",
            Some("Revoked") => "revoked",
            Some(status) => status,
            None => "status unavailable",
        };
        let allowed = if !warning
            && report.tcb_status.is_some()
            && report.tcb_status.as_deref() != Some("UpToDate")
        {
            " (allowed by appraisal policy)"
        } else {
            ""
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
            format!(
                "Intel TDX · verified by Trustee · TCB {tcb}{allowed}{appraisal} · ref {reference}"
            ),
        )
    };
    result.transition_time = timestamp(report.status_changed_at.unwrap_or(report.attested_at));
    result
}

#[cfg(test)]
mod tests;
