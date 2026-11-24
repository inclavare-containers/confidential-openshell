use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header};
use openshell_attestation_observer::{
    Observer,
    proto::{self, kbs_plugin_server::KbsPlugin},
    summarize,
};
use rcgen::KeyPair;
use serde_json::{Value, json};
use std::fs;

fn claims() -> Value {
    json!({"iat": 100, "exp": 200, "submods": {"cpu0": {
        "ear_status": "affirming", "ear_appraisal_policy_ids": ["default"],
        "ear_trustworthiness_vector": {"hardware": 2},
        "ear_attester_claims": {"tee": "tdx", "claims": {"tcb_status": "UpToDate", "quote": {"body": {"mr_td": "b".repeat(96)}},
            "uefi_event_logs": [{"type_name":"EV_EVENT_TAG", "details": {"unicode_name": "AAEL",
                "data": {"operation": "InitData", "domain": "github.com/confidential-containers", "content": {"digest": format!("sha384:{}", "a".repeat(96))}}}}]}}
    }}})
}
fn signed(key: &KeyPair, value: &Value) -> String {
    jsonwebtoken::encode(
        &Header::new(Algorithm::ES256),
        value,
        &EncodingKey::from_ec_pem(key.serialize_pem().as_bytes()).unwrap(),
    )
    .unwrap()
}

#[test]
fn historical_signature_and_unambiguous_measurement_required() {
    let key = KeyPair::generate().unwrap();
    let public = DecodingKey::from_ec_pem(key.public_key_pem().as_bytes()).unwrap();
    let value = claims();
    let token = signed(&key, &value);
    let report = summarize(&token, &public, 1000).unwrap(); // Expired but historical.
    assert_eq!(report.initdata_sha384, "a".repeat(96));
    assert_eq!(report.measurements.len(), 1);
    let mut native = value.clone();
    native["submods"]["cpu0"]["ear_attester_claims"]["claims"]["quote"]["body"]["mr_config_id"] =
        json!("c".repeat(96));
    assert_eq!(
        summarize(&signed(&key, &native), &public, 1000)
            .unwrap()
            .initdata_sha384,
        "c".repeat(96)
    );
    assert!(!serde_json::to_string(&report).unwrap().contains(&token));
    assert!(
        summarize(
            &signed(&KeyPair::generate().unwrap(), &value),
            &public,
            1000
        )
        .is_err()
    );
    for mode in ["duplicate", "domain", "future", "status"] {
        let mut bad = value.clone();
        let path = "/submods/cpu0/ear_attester_claims/claims/uefi_event_logs";
        match mode {
            "duplicate" => {
                let events = bad.pointer_mut(path).unwrap().as_array_mut().unwrap();
                events.push(events[0].clone());
            }
            "domain" => {
                bad.pointer_mut(path).unwrap()[0]["details"]["data"]["domain"] = json!("wrong");
            }
            "future" => {
                bad["iat"] = json!(2000);
                bad["exp"] = json!(3000);
            }
            _ => bad["submods"]["cpu0"]["ear_status"] = json!("unknown"),
        }
        assert!(
            summarize(&signed(&key, &bad), &public, 1000).is_err(),
            "{mode}"
        );
    }
}

#[tokio::test]
async fn partial_sessions_retry_latest_survives_restart_and_source_outage() {
    let temp = tempfile::tempdir().unwrap();
    let sessions = temp.path().join("sessions");
    let output = temp.path().join("reports");
    fs::create_dir(&sessions).unwrap();
    let key = KeyPair::generate().unwrap();
    let public = key.public_key_pem();
    let observer = Observer::new(sessions.clone(), output.clone(), public.as_bytes()).unwrap();
    let record = sessions.join("session");
    for index in ["#expiry", "#expiry.tmp"] {
        fs::write(record.parent().unwrap().join(index), b"{}").unwrap();
    }
    fs::write(&record, br#"{"Authed":{}}"#).unwrap();
    observer.scan().await;
    assert!(observer.observation(&"a".repeat(96)).await.report.is_none());
    fs::write(&record, b"{partial").unwrap();
    observer.scan().await;
    assert_eq!(
        observer
            .observation(&"a".repeat(96))
            .await
            .collection
            .ignored_records,
        1
    );
    let token = signed(&key, &claims());
    fs::write(&record, json!({"Attested":{"token":token}}).to_string()).unwrap();
    observer.scan().await;
    let report = observer.observation(&"a".repeat(96)).await.report.unwrap();
    assert_eq!(report.attested_at, 100);
    // Failed persistence is retried on the next poll, including the same EAR.
    let mut newer = claims();
    newer["iat"] = json!(101);
    newer["submods"]["cpu0"]["ear_attester_claims"]["claims"]["tcb_status"] = json!("OutOfDate");
    fs::write(
        &record,
        json!({"Attested":{"token":signed(&key, &newer)}}).to_string(),
    )
    .unwrap();
    fs::rename(&output, temp.path().join("saved")).unwrap();
    observer.scan().await;
    assert!(
        !observer
            .observation(&"a".repeat(96))
            .await
            .collection
            .available
    );
    fs::rename(temp.path().join("saved"), &output).unwrap();
    observer.scan().await;
    assert_eq!(
        observer
            .observation(&"a".repeat(96))
            .await
            .report
            .unwrap()
            .attested_at,
        101
    );
    fs::write(&record, json!({"Attested":{"token":token}}).to_string()).unwrap();
    observer.scan().await;
    fs::remove_dir_all(&sessions).unwrap();
    let restarted = Observer::new(sessions, output.clone(), public.as_bytes()).unwrap();
    restarted.scan().await;
    let observation = restarted.observation(&"a".repeat(96)).await;
    assert!(!observation.collection.available);
    assert_eq!(observation.report.unwrap().attested_at, 101);
    let stored = fs::read_to_string(output.join(format!("{}.json", "a".repeat(96)))).unwrap();
    assert!(!stored.contains(&token));
    assert!(!stored.contains("tee-pubkey"));
}

#[tokio::test]
async fn plugin_always_requires_admin_and_is_read_only() {
    let temp = tempfile::tempdir().unwrap();
    let key = KeyPair::generate().unwrap();
    let observer = Observer::new(
        temp.path().join("sessions"),
        temp.path().join("out"),
        key.public_key_pem().as_bytes(),
    )
    .unwrap();
    assert!(
        observer
            .validate_auth(tonic::Request::new(proto::ValidateAuthRequest::default()))
            .await
            .unwrap()
            .into_inner()
            .requires_admin_auth
    );
    for method in ["POST", "DELETE", "GET"] {
        let response = observer
            .handle(tonic::Request::new(proto::PluginRequest {
                method: method.into(),
                path: vec!["a".repeat(96)],
                ..Default::default()
            }))
            .await;
        assert_eq!(response.is_ok(), method == "GET");
        if let Ok(response) = response {
            assert_eq!(response.into_inner().status_code, 200);
        }
    }
}

#[tokio::test]
async fn stable_references_watermarks_and_status_times_survive_restart() {
    let temp = tempfile::tempdir().unwrap();
    let sessions = temp.path().join("sessions");
    let output = temp.path().join("reports");
    fs::create_dir(&sessions).unwrap();
    let key = KeyPair::generate().unwrap();
    let public = key.public_key_pem();
    let observer = Observer::new(sessions.clone(), output.clone(), public.as_bytes()).unwrap();
    let write = |value: &Value| {
        fs::write(
            sessions.join("session"),
            json!({"Attested":{"token":signed(&key, value)}}).to_string(),
        )
        .unwrap();
    };
    let mut value = claims();
    write(&value);
    observer.scan().await;
    let first = observer.observation(&"a".repeat(96)).await.report.unwrap();
    value["iat"] = json!(120);
    write(&value);
    observer.scan().await;
    let retained = observer.observation(&"a".repeat(96)).await.report.unwrap();
    assert_eq!(retained.attested_at, 100);
    assert_eq!(retained.latest_attested_at, Some(120));
    assert_eq!(retained.ear_sha256, first.ear_sha256);
    // Neither none nor late contradictory evidence may overwrite the latest known result.
    value["iat"] = json!(140);
    value["submods"]["cpu0"]["ear_status"] = json!("none");
    write(&value);
    observer.scan().await;
    value["iat"] = json!(110);
    value["submods"]["cpu0"]["ear_status"] = json!("contraindicated");
    write(&value);
    observer.scan().await;
    let restarted = Observer::new(sessions.clone(), output.clone(), public.as_bytes()).unwrap();
    assert_eq!(
        restarted.observation(&"a".repeat(96)).await.report.unwrap(),
        retained
    );
    // A new warning changes the represented evidence but not the True status time.
    value["iat"] = json!(150);
    value["submods"]["cpu0"]["ear_status"] = json!("warning");
    write(&value);
    restarted.scan().await;
    let warning = restarted.observation(&"a".repeat(96)).await.report.unwrap();
    assert_ne!(warning.ear_sha256, first.ear_sha256);
    assert_eq!(warning.status_changed_at, Some(100));
    assert!(
        output
            .join("by-ref")
            .join(format!("{}.json", first.ear_sha256))
            .exists()
    );
    assert!(
        output
            .join("by-ref")
            .join(format!("{}.json", warning.ear_sha256))
            .exists()
    );
    value["iat"] = json!(160);
    value["submods"]["cpu0"]["ear_status"] = json!("contraindicated");
    write(&value);
    restarted.scan().await;
    let rejected = restarted.observation(&"a".repeat(96)).await.report.unwrap();
    assert_eq!(rejected.status_changed_at, Some(160));
    let again = Observer::new(sessions, output, public.as_bytes()).unwrap();
    assert_eq!(
        again.observation(&"a".repeat(96)).await.report.unwrap(),
        rejected
    );
}

#[tokio::test]
async fn invalid_key_degrades_collection_and_recovers_without_losing_history() {
    let temp = tempfile::tempdir().unwrap();
    let sessions = temp.path().join("sessions");
    fs::create_dir(&sessions).unwrap();
    let path = temp.path().join("public.pem");
    fs::write(&path, "invalid key").unwrap();
    let observer =
        Observer::with_key_file(sessions.clone(), temp.path().join("out"), path.clone()).unwrap();
    observer.scan().await;
    assert!(
        !observer
            .observation(&"a".repeat(96))
            .await
            .collection
            .available
    );
    let key = KeyPair::generate().unwrap();
    fs::write(&path, key.public_key_pem()).unwrap();
    fs::write(
        sessions.join("session"),
        json!({"Attested":{"token":signed(&key, &claims())}}).to_string(),
    )
    .unwrap();
    observer.scan().await;
    let good = observer.observation(&"a".repeat(96)).await;
    assert!(good.collection.available);
    assert!(good.report.is_some());
    fs::write(&path, "bad rotation").unwrap();
    observer.scan().await;
    let degraded = observer.observation(&"a".repeat(96)).await;
    assert!(!degraded.collection.available);
    assert_eq!(degraded.report, good.report);
}
