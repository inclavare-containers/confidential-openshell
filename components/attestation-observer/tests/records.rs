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
        "ear.status": "affirming", "ear.appraisal-policy-id": "default",
        "ear.trustworthiness-vector": {"hardware": 2},
        "ear.veraison.annotated-evidence": {"tdx": {"tcb_status": "UpToDate", "quote": {"body": {"mr_td": "b".repeat(96)}},
            "uefi_event_logs": [{"type_name":"EV_EVENT_TAG", "details": {"unicode_name": "AAEL",
                "data": {"operation": "initdata", "domain": "confidentialcontainers.org", "content": "a".repeat(96)}}}]}}
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
        let path = "/submods/cpu0/ear.veraison.annotated-evidence/tdx/uefi_event_logs";
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
            _ => bad["submods"]["cpu0"]["ear.status"] = json!("unknown"),
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
