use jsonwebtoken::{Algorithm, EncodingKey, Header};
use openshell_attestation_observer::{Observation, is_digest, now};
use serde::Deserialize;
use serde_json::json;
use std::{
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};
use tokio::sync::Mutex;

#[derive(Clone, Deserialize)]
struct Config {
    kbs_url: String,
    ca_cert: PathBuf,
    admin_key: PathBuf,
}

#[derive(PartialEq, Eq)]
struct Stamp(u64, u64, u64, i64, i64);

async fn stamp(path: &Path) -> Result<Stamp, &'static str> {
    let m = tokio::fs::metadata(path)
        .await
        .map_err(|_| "configuration unavailable")?;
    Ok(Stamp(m.dev(), m.ino(), m.len(), m.ctime(), m.ctime_nsec()))
}

struct Transport {
    origin: reqwest::Url,
    client: reqwest::Client,
    key: EncodingKey,
}

struct Cached {
    config: Config,
    stamps: [Stamp; 3],
    transport: Arc<Transport>,
}

pub(super) struct Client {
    path: PathBuf,
    cached: Mutex<Option<Cached>>,
}

impl Client {
    pub(super) fn new(path: PathBuf) -> Self {
        Self {
            path,
            cached: Mutex::new(None),
        }
    }

    async fn transport(&self) -> Result<Arc<Transport>, &'static str> {
        let mut cached = self.cached.lock().await;
        let config_stamp = stamp(&self.path).await?;
        if let Some(previous) = cached.as_ref()
            && previous.stamps[0] == config_stamp
            && previous.stamps[1] == stamp(&previous.config.ca_cert).await?
            && previous.stamps[2] == stamp(&previous.config.admin_key).await?
        {
            return Ok(previous.transport.clone());
        }
        // A failed reload never falls back to an obsolete CA or admin key.
        *cached = None;
        let config: Config = serde_json::from_slice(
            &tokio::fs::read(&self.path)
                .await
                .map_err(|_| "configuration unavailable")?,
        )
        .map_err(|_| "invalid configuration")?;
        let origin = reqwest::Url::parse(&config.kbs_url).map_err(|_| "invalid origin")?;
        if origin.scheme() != "https"
            || origin.host_str().is_none()
            || !origin.username().is_empty()
            || origin.password().is_some()
            || origin.path() != "/"
            || origin.query().is_some()
            || origin.fragment().is_some()
        {
            return Err("expected HTTPS origin");
        }
        let stamps = [
            config_stamp,
            stamp(&config.ca_cert).await?,
            stamp(&config.admin_key).await?,
        ];
        let ca = tokio::fs::read(&config.ca_cert)
            .await
            .map_err(|_| "CA unavailable")?;
        let key = tokio::fs::read(&config.admin_key)
            .await
            .map_err(|_| "admin identity unavailable")?;
        if stamps
            != [
                stamp(&self.path).await?,
                stamp(&config.ca_cert).await?,
                stamp(&config.admin_key).await?,
            ]
        {
            return Err("configuration changed while reading");
        }
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let client = reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .tls_built_in_root_certs(false)
            .add_root_certificate(reqwest::Certificate::from_pem(&ca).map_err(|_| "invalid CA")?)
            .timeout(Duration::from_secs(2))
            .build()
            .map_err(|_| "client unavailable")?;
        let transport = Arc::new(Transport {
            origin,
            client,
            key: EncodingKey::from_ec_pem(&key).map_err(|_| "invalid admin identity")?,
        });
        *cached = Some(Cached {
            config,
            stamps,
            transport: transport.clone(),
        });
        Ok(transport)
    }

    pub(super) async fn query(&self, digest: &str) -> Result<Observation, &'static str> {
        if !is_digest(digest) {
            return Err("invalid digest");
        }
        let transport = self.transport().await?;
        let timestamp = now();
        let jwt = jsonwebtoken::encode(&Header::new(Algorithm::ES256), &json!({
            "iss": "confidential-openshell-driver", "aud": "kbs-admin", "role": "confidential-openshell",
            "nbf": timestamp.saturating_sub(10), "exp": timestamp + 60
        }), &transport.key).map_err(|_| "signing failed")?;
        let mut url = transport.origin.clone();
        url.set_path(&format!("/kbs/v0/external/attestation-reports/{digest}"));
        let mut response = transport
            .client
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
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn transport_is_reused_and_all_three_inputs_invalidate_it() {
        let area = tempfile::tempdir().unwrap();
        let ca = area.path().join("ca.pem");
        let key = area.path().join("key.pem");
        let path = area.path().join("config.json");
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        std::fs::write(&ca, cert.cert.pem()).unwrap();
        std::fs::write(&key, cert.key_pair.serialize_pem()).unwrap();
        let config = json!({"kbs_url":"https://localhost:1234", "ca_cert":ca, "admin_key":key});
        std::fs::write(&path, config.to_string()).unwrap();
        let client = Client::new(path.clone());
        let mut previous = client.transport().await.unwrap();
        assert!(Arc::ptr_eq(&previous, &client.transport().await.unwrap()));
        for target in [&key, &ca, &path] {
            // Atomic replacement, even with identical bytes, must invalidate the cache.
            let replacement = area.path().join("replacement");
            std::fs::write(&replacement, std::fs::read(target).unwrap()).unwrap();
            std::fs::rename(&replacement, target).unwrap();
            let current = client.transport().await.unwrap();
            assert!(!Arc::ptr_eq(&previous, &current));
            previous = current;
        }
        std::fs::write(&key, "invalid rotated key").unwrap();
        assert!(client.transport().await.is_err());
        std::fs::write(&key, cert.key_pair.serialize_pem()).unwrap();
        assert!(client.transport().await.is_ok());
    }
}
