use super::*;
use openshell_attestation_observer::Collection;
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
            attested_at: 100,
            token_expires_at: 200,
            observed_at: now(),
            ear_sha256: "b".repeat(64),
            appraisal: "affirming".into(),
            policy_id: "default".into(),
            tee: "tdx".into(),
            tcb_status: Some("UpToDate".into()),
            trustworthiness: BTreeMap::new(),
            measurements: BTreeMap::new(),
            latest_attested_at: None,
            status_changed_at: None,
        }),
    }
}

async fn register(reports: &Reports) -> Vec<SandboxCondition> {
    reports
        .conditions("sandbox", "uid", Some(&[binding(&"a".repeat(96))]), true)
        .await
}

async fn finish(reports: &Reports, observation: Result<Observation, &'static str>) {
    reports.views.lock().await.get_mut("sandbox").unwrap().roles[1].job = Some(42);
    reports.complete("sandbox", "uid", 1, 42, observation).await;
}

#[test]
fn appraisal_messages_and_timestamps() {
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
            "TCB out of date (allowed by appraisal policy)",
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
            Some("ConfigurationNeeded"),
            "True",
            "AttestedWithWarning",
            "TCB configuration needed",
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
            Some("Revoked"),
            "False",
            "AttestationRejected",
            "Trustee rejected the evidence",
        ),
    ] {
        let mut report = observation().report.unwrap();
        report.appraisal = appraisal.into();
        report.tcb_status = tcb.map(str::to_owned);
        let c = attested(TYPES[1], &report);
        assert_eq!((c.status.as_str(), c.reason.as_str()), (status, reason));
        assert!(c.message.contains(text), "{}", c.message);
        assert!(c.message.ends_with(" · ref bbbbbbbb"));
        assert_eq!(c.message.lines().count(), 1);
        assert_eq!(c.transition_time.unwrap().seconds, 100);
        if appraisal == "warning" {
            assert!(!c.message.contains("allowed by"));
        }
    }
}

#[tokio::test]
async fn only_semantic_changes_notify_and_status_alone_changes_time() {
    let reports = Reports::build(PathBuf::from("/not-configured"));
    let mut changes = reports.subscribe();
    register(&reports).await;
    finish(&reports, Ok(observation())).await;
    assert_eq!(changes.try_recv().unwrap(), "sandbox");
    let initial = register(&reports).await;
    assert_eq!(initial[1].transition_time.unwrap().seconds, 100);
    let mut repeated = observation();
    repeated.collection.last_scan_at = Some(1); // No driver wall-clock freshness decisions.
    repeated.report.as_mut().unwrap().attested_at = 120;
    repeated.report.as_mut().unwrap().ear_sha256 = "c".repeat(64);
    finish(&reports, Ok(repeated)).await;
    assert_eq!(register(&reports).await, initial);
    assert!(changes.try_recv().is_err());
    finish(&reports, Err("outage")).await;
    assert_eq!(register(&reports).await, initial);
    assert!(changes.try_recv().is_err());
    let mut warning = observation();
    warning.report.as_mut().unwrap().attested_at = 140;
    warning.report.as_mut().unwrap().tcb_status = Some("OutOfDate".into());
    finish(&reports, Ok(warning)).await;
    assert_eq!(changes.try_recv().unwrap(), "sandbox");
    let shown = register(&reports).await;
    assert_eq!(shown[1].reason, "AttestedWithWarning");
    assert_eq!(shown[1].transition_time.unwrap().seconds, 100);
    let mut rejected = observation();
    rejected.report.as_mut().unwrap().attested_at = 160;
    rejected.report.as_mut().unwrap().appraisal = "contraindicated".into();
    finish(&reports, Ok(rejected)).await;
    assert_eq!(changes.try_recv().unwrap(), "sandbox");
    let shown = register(&reports).await;
    assert_eq!(shown[1].status, "False");
    assert_eq!(shown[1].transition_time.unwrap().seconds, 160);
    // Delayed old success, missing records and none cannot undo a conclusion.
    for value in [Some("affirming"), Some("none"), None] {
        let mut record = observation();
        if let Some(appraisal) = value {
            record.report.as_mut().unwrap().appraisal = appraisal.into();
        } else {
            record.report = None;
        }
        finish(&reports, Ok(record)).await;
        assert_eq!(register(&reports).await, shown);
    }
    assert!(changes.try_recv().is_err());
}

#[tokio::test(start_paused = true)]
async fn deadline_notifies_without_snapshot_reads_and_does_not_reset_transition() {
    let reports = Reports::build(PathBuf::from("/not-configured"));
    let initial = reports.conditions("sandbox", "uid", Some(&[]), true).await;
    let mut changes = reports.subscribe();
    tokio::time::advance(PENDING_WINDOW + Duration::from_secs(1)).await;
    reports.poll_due().await;
    assert_eq!(changes.try_recv().unwrap(), "sandbox");
    let shown = reports.conditions("sandbox", "uid", Some(&[]), true).await;
    assert_eq!(shown[1].reason, "AttestationStatusUnavailable");
    assert_eq!(
        shown[1].message,
        "no Trustee record captured for this attempt"
    );
    assert_eq!(shown[1].transition_time, initial[1].transition_time);
    reports.poll_due().await;
    assert!(changes.try_recv().is_err());
}

#[tokio::test]
async fn binding_identity_stop_delete_and_late_queries_never_reuse_wrong_history() {
    let reports = Reports::build(PathBuf::from("/not-configured"));
    register(&reports).await;
    finish(&reports, Ok(observation())).await;
    let original = register(&reports).await;
    assert_eq!(
        reports.conditions("sandbox", "uid", None, true).await[1].reason,
        "AttestationStatusUnavailable"
    );
    assert_eq!(register(&reports).await[1].message, original[1].message);
    reports.views.lock().await.get_mut("sandbox").unwrap().roles[1].job = Some(77);
    let mut next = binding(&"c".repeat(96));
    next.attempt_id = "new-attempt".into();
    reports
        .conditions("sandbox", "uid", Some(&[next]), true)
        .await;
    reports
        .complete("sandbox", "uid", 1, 77, Ok(observation()))
        .await;
    assert!(
        reports.views.lock().await["sandbox"].roles[1]
            .report
            .is_none()
    );
    let stopped = reports.conditions("sandbox", "uid", Some(&[]), false).await;
    assert!(stopped.iter().all(|c| c.reason == "NotRunning"));
    assert_eq!(register(&reports).await[1].reason, "AttestationPending");
    finish(&reports, Ok(observation())).await;
    assert_eq!(
        reports
            .conditions(
                "sandbox",
                "replacement-uid",
                Some(&[binding(&"a".repeat(96))]),
                true
            )
            .await[1]
            .status,
        "Unknown"
    );
    reports.forget("sandbox").await;
    reports
        .complete("sandbox", "replacement-uid", 1, 77, Ok(observation()))
        .await;
    assert!(reports.views.lock().await.is_empty());
}

#[tokio::test]
async fn poller_queries_and_notifies_without_get_or_list() {
    let reports = Reports::new(PathBuf::from("/not-configured"));
    let mut changes = reports.subscribe();
    assert_eq!(register(&reports).await[1].reason, "AttestationPending");
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(2), changes.recv())
            .await
            .unwrap()
            .unwrap(),
        "sandbox"
    );
    let views = reports.views.lock().await;
    assert_eq!(
        views["sandbox"].roles[1].condition.reason,
        "AttestationStatusUnavailable"
    );
    assert!(views["sandbox"].roles[1].next_query > Instant::now());
}

#[tokio::test]
async fn roles_are_independent_and_conclusive_results_back_off() {
    let reports = Reports::build(PathBuf::from("/not-configured"));
    let mut supervisor = binding(&"d".repeat(96));
    supervisor.role = "supervisor".into();
    reports
        .conditions(
            "sandbox",
            "uid",
            Some(&[supervisor, binding(&"a".repeat(96))]),
            true,
        )
        .await;
    finish(&reports, Ok(observation())).await;
    let views = reports.views.lock().await;
    let roles = &views["sandbox"].roles;
    assert_eq!(roles[0].condition.status, "Unknown");
    assert_eq!(roles[1].condition.status, "True");
    assert!(roles[1].next_query.duration_since(Instant::now()) > Duration::from_secs(55));
    assert_eq!(roles[1].condition.r#type, "WorkloadAttested");
}

#[tokio::test]
#[ignore = "requires the temporary released-KBS fixture from check-attestation-reports.py"]
async fn released_kbs_attestation_report_query() {
    let config = PathBuf::from(std::env::var("OPENSHELL_TEST_REPORT_CONFIG").unwrap());
    let reports = Reports::new(config);
    let mut changes = reports.subscribe();
    register(&reports).await;
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            changes.recv().await.unwrap();
            if reports.views.lock().await["sandbox"].roles[1]
                .condition
                .status
                == "True"
            {
                break;
            }
        }
    })
    .await
    .unwrap();
    let conditions = register(&reports).await;
    assert_eq!(conditions[1].reason, "Attested");
    assert!(conditions[1].transition_time.is_some());
    let encoded = conditions[1].encode_to_vec();
    if let Ok(path) = std::env::var("OPENSHELL_TEST_REPORT_CONDITION") {
        std::fs::write(path, &encoded).unwrap();
    }
    let decoded = SandboxCondition::decode(encoded.as_slice()).unwrap();
    assert_eq!(decoded.r#type, "WorkloadAttested");
    assert!(
        decoded
            .message
            .starts_with("Intel TDX · verified by Trustee · TCB up to date · ref ")
    );
}

#[tokio::test]
async fn persisted_observer_transition_is_not_lost_when_driver_misses_intermediate_state() {
    let reports = Reports::build(PathBuf::from("/not-configured"));
    register(&reports).await;
    finish(&reports, Ok(observation())).await;
    // Observer saw a rejection then recovery while this driver's poll was delayed.
    let mut recovery = observation();
    let report = recovery.report.as_mut().unwrap();
    report.attested_at = 180;
    report.latest_attested_at = Some(190);
    report.status_changed_at = Some(180);
    report.ear_sha256 = "c".repeat(64);
    finish(&reports, Ok(recovery)).await;
    let shown = register(&reports).await;
    assert_eq!(shown[1].status, "True");
    assert_eq!(shown[1].transition_time.unwrap().seconds, 180);
    assert!(shown[1].message.ends_with("ref cccccccc"));
}
