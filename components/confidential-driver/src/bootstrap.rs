//! Trusted-host publisher for upstream CDH signed vault references.
//!
//! Private staging is reconciled to the authenticated Trustee management API.
//! Kubernetes receives only the signed `sealed.<JWS>` descriptor. KBS policy
//! must independently authorize both its signer and each file from verified
//! measured initdata; fields in the binding record are not attestation claims.

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use fs2::FileExt;
use ring::{
    rand::{SecureRandom, SystemRandom},
    signature::{
        ECDSA_P256_SHA256_FIXED, ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair,
        UnparsedPublicKey,
    },
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    process::Command,
};
use thiserror::Error;

const SIGNER_URI: &str = "kbs:///default/bootstrap-signer/key";
// The management client has its own 120s request budget. Bound the whole
// renderer process group as well, including startup and lock acquisition.
const PUBLICATION_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(150);

#[derive(Debug, Error)]
pub enum StoreError {
    #[error("invalid bootstrap identity or digest: {0}")]
    Invalid(&'static str),
    #[error("bootstrap identity has been revoked")]
    Revoked,
    #[error("bootstrap policy renderer is not configured or failed")]
    Policy,
    #[error("bootstrap file already exists with different content or binding")]
    Conflict,
    #[error("bootstrap store path is a symbolic link or is not a regular file")]
    UnsafePath,
    #[error("bootstrap store IO: {0}")]
    Io(#[from] std::io::Error),
    #[error("bootstrap store serialization: {0}")]
    Json(#[from] serde_json::Error),
    #[error("bootstrap store cryptography failed")]
    Crypto,
    #[error("Trustee management publication failed: {0}")]
    Publication(String),
    #[error("bootstrap cleanup remains pending: {0}")]
    Cleanup(String),
}
pub type Result<T> = std::result::Result<T, StoreError>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BootstrapRole {
    Workload,
    Supervisor,
}
impl BootstrapRole {
    pub(super) fn as_str(self) -> &'static str {
        match self {
            Self::Workload => "workload",
            Self::Supervisor => "supervisor",
        }
    }
}

/// The descriptor is safe to place in a Kubernetes Secret data value. The
/// resource URI identifies raw bytes served by Trustee after attestation.
#[derive(Clone, Debug)]
pub struct PublishedSecret {
    pub(super) sealed_descriptor: String,
    #[cfg(test)]
    pub(super) resource_uri: String,
    #[cfg(test)]
    pub(super) resource_path: String,
    #[cfg(test)]
    pub(super) binding_path: PathBuf,
}

#[derive(Clone, Debug)]
pub struct PlannedSecret {
    pub(super) resource_uri: String,
    pub(super) resource_path: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
pub struct Binding {
    pub(super) resource_path: String,
    pub(super) initdata_sha384: String,
    pub(super) role: String,
    pub(super) generation: String,
    pub(super) sandbox_id: String,
    pub(super) sandbox_cr_uid: String,
    pub(super) attempt_id: String,
    pub(super) key: String,
    pub(super) resource_sha256: String,
    pub(super) identity_sha256: String,
}

#[derive(Debug, Serialize, Deserialize, Eq, PartialEq)]
pub struct WorkspaceBinding {
    pub(super) resource_path: String,
    pub(super) initdata_sha384: String,
    pub(super) namespace: String,
    pub(super) sandbox_cr_uid: String,
    pub(super) resource_sha256: String,
    pub(super) identity_sha256: String,
}

#[derive(Debug, Serialize, Deserialize, Eq, PartialEq)]
pub struct WorkspaceVolume {
    pub(super) pvc_name: String,
    pub(super) pv_uid_or_name: Option<String>,
    pub(super) cloud_disk_id: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Eq, PartialEq)]
pub struct WorkspaceVolumeJournal {
    pub(super) namespace: String,
    pub(super) sandbox_cr_uid: String,
    pub(super) identity_sha256: String,
    pub(super) volumes: Vec<WorkspaceVolume>,
}

#[derive(Debug, Serialize, Deserialize, Eq, PartialEq)]
pub struct WorkspaceOwner {
    pub(super) sandbox_id: String,
    pub(super) namespace: String,
    pub(super) sandbox_cr_uid: String,
    pub(super) workspace_identity_sha256: String,
}

// Original values stay on T so a restart never has to trust Kubernetes env.
// Deliberately omit Debug: this record can contain user credentials.
#[derive(Serialize, Deserialize, Eq, PartialEq)]
struct WorkloadEnvironment {
    sandbox_id: String,
    namespace: String,
    sandbox_cr_uid: String,
    environment: std::collections::HashMap<String, String>,
}

/// Durable deletion fence. Identities are captured while the old CR UID is
/// still known, so retries cannot revoke a replacement CR's new attempt.
#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
pub struct PendingDelete {
    pub(super) sandbox_id: String,
    pub(super) namespace: String,
    pub(super) sandbox_cr_uid: String,
    pub(super) bootstrap_identities: Vec<String>,
}

#[derive(Clone, Serialize, Deserialize, PartialEq)]
struct ActiveAttempt {
    sandbox_id: String,
    sandbox_cr_uid: String,
    generation: String,
    attempt: String,
}

pub struct BootstrapStore {
    repository: PathBuf,
    state: PathBuf,
    signing_key: PathBuf,
    policy: Option<(PathBuf, PathBuf, PathBuf)>,
    trustee_config: Option<PathBuf>,
}

impl BootstrapStore {
    /// `signing_key_path` is private PKCS#8 key state. Its parent contains
    /// binding records and revocation tombstones; it must be on durable local
    /// storage. All writers for this store share the advisory lock there.
    pub(super) fn open(
        repository_dir: impl AsRef<Path>,
        signing_key_path: impl AsRef<Path>,
    ) -> Result<Self> {
        let repository = repository_dir.as_ref().to_path_buf();
        let signing_key = signing_key_path.as_ref().to_path_buf();
        let state = signing_key
            .parent()
            .ok_or(StoreError::Invalid("signing key path"))?
            .to_path_buf();
        ensure_private_dir(&state)?;
        ensure_private_dir(&repository)?;
        ensure_private_dir(&state.join("bindings"))?;
        ensure_private_dir(&state.join("descriptors"))?;
        ensure_private_dir(&state.join("revoked"))?;
        ensure_private_dir(&state.join("revoking"))?;
        ensure_private_dir(&state.join("workspace-keys"))?;
        ensure_private_dir(&state.join("workspace-bindings"))?;
        ensure_private_dir(&state.join("workspace-journal"))?;
        ensure_private_dir(&state.join("workspace-owners"))?;
        ensure_private_dir(&state.join("pending-deletes"))?;
        ensure_private_dir(&state.join("workload-environments"))?;
        ensure_private_dir(&state.join("launch-intents"))?;
        ensure_private_dir(&state.join("active-attempts"))?;
        ensure_private_dir(&state.join("pending-revocations"))?;
        let store = Self {
            repository,
            state,
            signing_key,
            policy: None,
            trustee_config: None,
        };
        store.with_lock(|| {
            store.clean_temporary_files()?;
            let pair = store.load_or_create_signer()?;
            store.publish_signer(&pair)?;
            Ok(())
        })?;
        Ok(store)
    }

    /// Offline store fixture: render private policies without contacting Trustee.
    #[cfg(test)]
    pub(super) fn open_with_policies(
        repository_dir: impl AsRef<Path>,
        signing_key_path: impl AsRef<Path>,
        renderer_script: impl AsRef<Path>,
        kbs_policy_output: impl AsRef<Path>,
        as_policy_output: impl AsRef<Path>,
    ) -> Result<Self> {
        Self::open_configured(
            repository_dir,
            signing_key_path,
            renderer_script,
            kbs_policy_output,
            as_policy_output,
            None,
        )
    }

    pub(super) fn open_with_trustee(
        repository_dir: impl AsRef<Path>,
        signing_key_path: impl AsRef<Path>,
        renderer_script: impl AsRef<Path>,
        kbs_policy_output: impl AsRef<Path>,
        as_policy_output: impl AsRef<Path>,
        trustee_config: &Path,
    ) -> Result<Self> {
        Self::open_configured(
            repository_dir,
            signing_key_path,
            renderer_script,
            kbs_policy_output,
            as_policy_output,
            Some(trustee_config.to_path_buf()),
        )
    }

    fn open_configured(
        repository_dir: impl AsRef<Path>,
        signing_key_path: impl AsRef<Path>,
        renderer_script: impl AsRef<Path>,
        kbs_policy_output: impl AsRef<Path>,
        as_policy_output: impl AsRef<Path>,
        trustee_config: Option<PathBuf>,
    ) -> Result<Self> {
        let mut store = Self::open(repository_dir, signing_key_path)?;
        store.trustee_config = trustee_config;
        store.policy = Some((
            renderer_script.as_ref().to_path_buf(),
            kbs_policy_output.as_ref().to_path_buf(),
            as_policy_output.as_ref().to_path_buf(),
        ));
        // A process can die immediately after writing a deletion fence.
        // Withdraw every marked raw resource before this constructor returns,
        // even if Trustee policy rendering is temporarily broken.
        let mut pending_error = None;
        for owner in store.pending_revocations()? {
            if let Err(error) =
                store.revoke_owned_sandbox(&owner.sandbox_id, Some(&owner.sandbox_cr_uid))
            {
                pending_error = Some(error);
            }
        }
        for marker in store.pending_deletes()? {
            if let Err(error) = store.revoke_pending_delete(&marker) {
                pending_error = Some(error);
            }
        }
        if let Some(error) = pending_error {
            return Err(error);
        }
        store.with_lock(|| {
            store.revoke_identities(std::iter::empty())?;
            store.refresh_policy()
        })?;
        Ok(store)
    }

    /// Stable URI planning for generation of measured initdata before bytes
    /// are published. No state is written and no trust decision is made.
    #[allow(clippy::unused_self)] // Keep planning paired with the store publishing API.
    pub(super) fn plan_file(
        &self,
        role: BootstrapRole,
        generation: &str,
        sandbox_id: &str,
        attempt_id: &str,
        key: &str,
    ) -> Result<PlannedSecret> {
        validate(role, generation, sandbox_id, attempt_id, Some(key), None)?;
        let id = file_hash(
            &identity_hash(role, generation, sandbox_id, attempt_id),
            key,
        );
        Ok(PlannedSecret {
            resource_uri: format!("kbs:///default/bootstrap/{id}"),
            resource_path: format!("resource/default/bootstrap/{id}"),
        })
    }

    #[allow(clippy::unused_self)] // Keep planning paired with the store publishing API.
    pub(super) fn plan_workspace_key(
        &self,
        namespace: &str,
        sandbox_cr_uid: &str,
    ) -> Result<PlannedSecret> {
        validate_workspace_identity(namespace, sandbox_cr_uid)?;
        let id = workspace_hash(namespace, sandbox_cr_uid);
        Ok(PlannedSecret {
            resource_uri: format!("kbs:///default/workspace/{id}"),
            resource_path: format!("resource/default/workspace/{id}"),
        })
    }

    pub(super) fn record_attempt(
        &self,
        sandbox_id: &str,
        namespace: &str,
        uid: &str,
        generation: &str,
        attempt: &str,
    ) -> Result<()> {
        validate(
            BootstrapRole::Workload,
            generation,
            sandbox_id,
            attempt,
            None,
            None,
        )?;
        validate_workspace_identity(namespace, uid)?;
        self.with_lock(|| {
            if self.has_pending_delete_for_sandbox(sandbox_id)? {
                return Err(StoreError::Revoked);
            }
            if self
                .state
                .join("pending-revocations")
                .join(format!("{}.json", workspace_hash(namespace, uid)))
                .exists()
            {
                return Err(StoreError::Revoked);
            }
            self.record_workspace_owner_locked(sandbox_id, namespace, uid)?;
            let record = ActiveAttempt {
                sandbox_id: sandbox_id.into(),
                sandbox_cr_uid: uid.into(),
                generation: generation.into(),
                attempt: attempt.into(),
            };
            let path = self
                .state
                .join("active-attempts")
                .join(format!("{}.json", workspace_hash(namespace, uid)));
            if path.try_exists()? {
                let previous: ActiveAttempt = serde_json::from_slice(&read_private(&path)?)?;
                if previous == record {
                    return Ok(());
                }
                if previous.sandbox_id != sandbox_id
                    || previous.sandbox_cr_uid != uid
                    || [BootstrapRole::Workload, BootstrapRole::Supervisor]
                        .iter()
                        .any(|role| {
                            !self
                                .tombstone(&identity_hash(
                                    *role,
                                    &previous.generation,
                                    sandbox_id,
                                    &previous.attempt,
                                ))
                                .exists()
                        })
                {
                    return Err(StoreError::Conflict);
                }
            }
            atomic_replace(&path, &serde_json::to_vec(&record)?)
        })
    }

    /// Display-only snapshot of T-owned bindings. Never takes the publication lock.
    /// Concurrent deletion/restart yields no binding, not an authorization decision.
    pub(super) fn attestation_bindings(
        &self,
        sandbox_id: &str,
        namespace: &str,
        uid: &str,
    ) -> Result<Vec<Binding>> {
        validate_workspace_identity(namespace, uid)?;
        let owner = workspace_hash(namespace, uid);
        if self
            .state
            .join("pending-revocations")
            .join(format!("{owner}.json"))
            .exists()
            || self.has_pending_delete_for_sandbox(sandbox_id)?
        {
            return Ok(Vec::new());
        }
        let path = self
            .state
            .join("active-attempts")
            .join(format!("{owner}.json"));
        if !path.try_exists()? {
            return Ok(Vec::new());
        }
        let active: ActiveAttempt = serde_json::from_slice(&read_private(&path)?)?;
        if active.sandbox_id != sandbox_id || active.sandbox_cr_uid != uid {
            return Ok(Vec::new());
        }
        let mut selected = std::collections::BTreeMap::<String, Binding>::new();
        for entry in fs::read_dir(self.state.join("bindings"))? {
            let binding: Binding = serde_json::from_slice(&read_regular(&entry?.path())?)?;
            if binding.sandbox_id != sandbox_id
                || binding.sandbox_cr_uid != uid
                || binding.generation != active.generation
                || binding.attempt_id != active.attempt
            {
                continue;
            }
            if self.tombstone(&binding.identity_sha256).exists()
                || self.revoking(&binding.identity_sha256).exists()
            {
                continue;
            }
            if let Some(previous) = selected.get(&binding.role)
                && previous.initdata_sha384 != binding.initdata_sha384
            {
                return Err(StoreError::Conflict);
            }
            selected.insert(binding.role.clone(), binding);
        }
        if serde_json::from_slice::<ActiveAttempt>(&read_private(&path)?)? != active {
            return Ok(Vec::new());
        }
        Ok(selected
            .into_values()
            .filter(|b| {
                !self.tombstone(&b.identity_sha256).exists()
                    && !self.revoking(&b.identity_sha256).exists()
            })
            .collect())
    }

    /// Locate authorizations from T, even when Kubernetes is unreachable or
    /// annotations have been removed. The caller holds the sandbox lifecycle gate.
    pub(super) fn revoke_owned_sandbox(
        &self,
        sandbox_id: &str,
        expected_uid: Option<&str>,
    ) -> Result<()> {
        validate_sandbox(sandbox_id)?;
        let mut errors = Vec::new();
        for owner in self.workspace_owners()?.into_iter().filter(|owner| {
            owner.sandbox_id == sandbox_id
                && expected_uid.is_none_or(|uid| owner.sandbox_cr_uid == uid)
        }) {
            let path = self
                .state
                .join("pending-revocations")
                .join(format!("{}.json", owner.workspace_identity_sha256));
            self.with_lock(|| {
                if !path.exists() {
                    atomic_new(&path, &serde_json::to_vec(&owner)?)?;
                }
                Ok(())
            })?;
            let mut complete = true;
            for result in [
                self.deauthorize_workspace_key(&owner.namespace, &owner.sandbox_cr_uid),
                self.revoke_sandbox_uid(sandbox_id, &owner.sandbox_cr_uid),
            ] {
                if let Err(error) = result {
                    complete = false;
                    errors.push(error.to_string());
                }
            }
            if complete {
                self.with_lock(|| {
                    fs::remove_file(&path)?;
                    sync_dir(path.parent().unwrap())
                })?;
            }
        }
        if errors.is_empty() {
            Ok(())
        } else {
            Err(StoreError::Cleanup(errors.join("; ")))
        }
    }

    pub(super) fn pending_revocations(&self) -> Result<Vec<WorkspaceOwner>> {
        let mut owners = Vec::new();
        for entry in fs::read_dir(self.state.join("pending-revocations"))? {
            let path = entry?.path();
            if path
                .file_name()
                .is_some_and(|name| name.to_string_lossy().starts_with('.'))
            {
                continue;
            }
            let owner: WorkspaceOwner = serde_json::from_slice(&read_private(&path)?)?;
            validate_sandbox(&owner.sandbox_id)?;
            validate_workspace_identity(&owner.namespace, &owner.sandbox_cr_uid)?;
            if owner.workspace_identity_sha256
                != workspace_hash(&owner.namespace, &owner.sandbox_cr_uid)
                || path.file_stem().and_then(|v| v.to_str())
                    != Some(owner.workspace_identity_sha256.as_str())
            {
                return Err(StoreError::Conflict);
            }
            owners.push(owner);
        }
        Ok(owners)
    }

    pub(super) fn record_launch(&self, launch: &crate::launch::LaunchIntent) -> Result<()> {
        validate_sandbox(&launch.sandbox_id)?;
        validate_workspace_identity(&launch.namespace, &launch.sandbox_cr_uid)?;
        let path = self.launch_path(&launch.namespace, &launch.sandbox_cr_uid);
        self.with_lock(|| {
            if self.has_pending_delete_for_sandbox(&launch.sandbox_id)? {
                return Err(StoreError::Revoked);
            }
            self.record_workspace_owner_locked(
                &launch.sandbox_id,
                &launch.namespace,
                &launch.sandbox_cr_uid,
            )?;
            if path.try_exists()? {
                let prior: crate::launch::LaunchIntent =
                    serde_json::from_slice(&read_private(&path)?)?;
                if prior != *launch {
                    return Err(StoreError::Conflict);
                }
            } else {
                atomic_new(&path, &serde_json::to_vec(launch)?)?;
            }
            Ok(())
        })
    }

    pub(super) fn load_launch(
        &self,
        sandbox_id: &str,
        namespace: &str,
        uid: &str,
    ) -> Result<crate::launch::LaunchIntent> {
        validate_sandbox(sandbox_id)?;
        validate_workspace_identity(namespace, uid)?;
        self.with_lock(|| {
            if self.has_pending_delete_for_sandbox(sandbox_id)? {
                return Err(StoreError::Revoked);
            }
            let launch: crate::launch::LaunchIntent =
                serde_json::from_slice(&read_private(&self.launch_path(namespace, uid))?)?;
            if launch.sandbox_id != sandbox_id
                || launch.namespace != namespace
                || launch.sandbox_cr_uid != uid
            {
                return Err(StoreError::Conflict);
            }
            Ok(launch)
        })
    }

    fn launch_path(&self, namespace: &str, uid: &str) -> PathBuf {
        self.state
            .join("launch-intents")
            .join(format!("{}.json", workspace_hash(namespace, uid)))
    }

    pub(super) fn record_workload_environment(
        &self,
        sandbox_id: &str,
        namespace: &str,
        sandbox_cr_uid: &str,
        environment: &std::collections::HashMap<String, String>,
    ) -> Result<()> {
        validate_sandbox(sandbox_id)?;
        validate_workspace_identity(namespace, sandbox_cr_uid)?;
        let record = WorkloadEnvironment {
            sandbox_id: sandbox_id.to_owned(),
            namespace: namespace.to_owned(),
            sandbox_cr_uid: sandbox_cr_uid.to_owned(),
            environment: environment.clone(),
        };
        let path = self.workload_environment(namespace, sandbox_cr_uid);
        self.with_lock(|| {
            if self.has_pending_delete_for_sandbox(sandbox_id)? {
                return Err(StoreError::Revoked);
            }
            // Keep cleanup discovery and env publication under one lock. A
            // crash or concurrent delete must not leave an unindexed secret.
            self.record_workspace_owner_locked(sandbox_id, namespace, sandbox_cr_uid)?;
            if path.try_exists()? {
                let prior: WorkloadEnvironment = serde_json::from_slice(&read_private(&path)?)?;
                if prior != record {
                    return Err(StoreError::Conflict);
                }
            } else {
                atomic_new(&path, &serde_json::to_vec(&record)?)?;
            }
            Ok(())
        })
    }

    pub(super) fn load_workload_environment(
        &self,
        sandbox_id: &str,
        namespace: &str,
        sandbox_cr_uid: &str,
    ) -> Result<std::collections::HashMap<String, String>> {
        validate_sandbox(sandbox_id)?;
        validate_workspace_identity(namespace, sandbox_cr_uid)?;
        self.with_lock(|| {
            if self.has_pending_delete_for_sandbox(sandbox_id)? {
                return Err(StoreError::Revoked);
            }
            let record: WorkloadEnvironment = serde_json::from_slice(&read_private(
                &self.workload_environment(namespace, sandbox_cr_uid),
            )?)?;
            if record.sandbox_id != sandbox_id
                || record.namespace != namespace
                || record.sandbox_cr_uid != sandbox_cr_uid
            {
                return Err(StoreError::Conflict);
            }
            Ok(record.environment)
        })
    }

    /// Persist the lookup needed to withdraw workspace access after the
    /// Kubernetes CR is gone. Call before any workspace authorization.
    pub(super) fn record_workspace_owner(
        &self,
        sandbox_id: &str,
        namespace: &str,
        sandbox_cr_uid: &str,
    ) -> Result<()> {
        self.with_lock(|| self.record_workspace_owner_locked(sandbox_id, namespace, sandbox_cr_uid))
    }

    fn record_workspace_owner_locked(
        &self,
        sandbox_id: &str,
        namespace: &str,
        sandbox_cr_uid: &str,
    ) -> Result<()> {
        validate_sandbox(sandbox_id)?;
        validate_workspace_identity(namespace, sandbox_cr_uid)?;
        let workspace_id = workspace_hash(namespace, sandbox_cr_uid);
        let owner = WorkspaceOwner {
            sandbox_id: sandbox_id.to_owned(),
            namespace: namespace.to_owned(),
            sandbox_cr_uid: sandbox_cr_uid.to_owned(),
            workspace_identity_sha256: workspace_id.clone(),
        };
        let path = self.workspace_owner(sandbox_id, &workspace_id);
        for item in fs::read_dir(self.state.join("workspace-owners"))? {
            let existing = self.read_workspace_owner(&item?.path())?;
            if existing.workspace_identity_sha256 == workspace_id && existing != owner {
                return Err(StoreError::Conflict);
            }
        }
        if path.exists() {
            if self.read_workspace_owner(&path)? != owner {
                return Err(StoreError::Conflict);
            }
        } else {
            atomic_new(&path, &serde_json::to_vec(&owner)?)?;
        }
        Ok(())
    }

    /// Fence new publication and snapshot only identities belonging to the
    /// CR being deleted. The caller must have verified this CR's UID before
    /// invoking this method. The marker survives process and Gateway loss.
    pub(super) fn begin_delete(
        &self,
        sandbox_id: &str,
        namespace: &str,
        sandbox_cr_uid: &str,
        current_attempt: Option<(&str, &str)>,
    ) -> Result<PendingDelete> {
        validate_sandbox(sandbox_id)?;
        validate_workspace_identity(namespace, sandbox_cr_uid)?;
        if let Some((generation, attempt)) = current_attempt {
            validate_generation(generation)?;
            validate_attempt(attempt)?;
        }
        if self.policy.is_none() {
            return Err(StoreError::Policy);
        }
        self.with_lock(|| {
            let path = self.pending_delete_path(sandbox_id, namespace, sandbox_cr_uid);
            if path.exists() {
                return self.read_pending_delete(&path);
            }
            let mut identities = std::collections::BTreeSet::new();
            if let Some((generation, attempt)) = current_attempt {
                for role in [BootstrapRole::Workload, BootstrapRole::Supervisor] {
                    identities.insert(identity_hash(role, generation, sandbox_id, attempt));
                }
            }
            for item in fs::read_dir(self.binding_directory())? {
                let binding: Binding = serde_json::from_slice(&read_regular(&item?.path())?)?;
                if binding.sandbox_id == sandbox_id && binding.sandbox_cr_uid == sandbox_cr_uid {
                    identities.insert(binding.identity_sha256);
                }
            }
            let active = self.state.join("active-attempts").join(format!(
                "{}.json",
                workspace_hash(namespace, sandbox_cr_uid)
            ));
            if active.try_exists()? {
                let record: ActiveAttempt = serde_json::from_slice(&read_private(&active)?)?;
                if record.sandbox_id != sandbox_id || record.sandbox_cr_uid != sandbox_cr_uid {
                    return Err(StoreError::Conflict);
                }
                for role in [BootstrapRole::Workload, BootstrapRole::Supervisor] {
                    identities.insert(identity_hash(
                        role,
                        &record.generation,
                        sandbox_id,
                        &record.attempt,
                    ));
                }
            }
            let marker = PendingDelete {
                sandbox_id: sandbox_id.to_owned(),
                namespace: namespace.to_owned(),
                sandbox_cr_uid: sandbox_cr_uid.to_owned(),
                bootstrap_identities: identities.into_iter().collect(),
            };
            atomic_new(&path, &serde_json::to_vec(&marker)?)?;
            Ok(marker)
        })
    }

    pub(super) fn pending_deletes(&self) -> Result<Vec<PendingDelete>> {
        self.with_lock(|| {
            let mut pending = Vec::new();
            for item in fs::read_dir(self.state.join("pending-deletes"))? {
                pending.push(self.read_pending_delete(&item?.path())?);
            }
            Ok(pending)
        })
    }

    pub(super) fn workspace_owners(&self) -> Result<Vec<WorkspaceOwner>> {
        self.with_lock(|| {
            fs::read_dir(self.state.join("workspace-owners"))?
                .map(|item| self.read_workspace_owner(&item?.path()))
                .collect()
        })
    }

    /// Revoke only the marker's old UID and frozen bootstrap identities.
    /// Retain the marker until resource retirement and CR/Pod deletion have
    /// also succeeded; a later tick can retry after any interruption.
    pub(super) fn revoke_pending_delete(&self, marker: &PendingDelete) -> Result<()> {
        if self.policy.is_none() {
            return Err(StoreError::Policy);
        }
        self.with_lock(|| {
            let path = self.pending_delete_path(
                &marker.sandbox_id,
                &marker.namespace,
                &marker.sandbox_cr_uid,
            );
            if self.read_pending_delete(&path)? != *marker {
                return Err(StoreError::Conflict);
            }
            self.revoke_identities(marker.bootstrap_identities.iter().cloned().chain(
                std::iter::once(format!(
                    "workspace-{}",
                    workspace_hash(&marker.namespace, &marker.sandbox_cr_uid)
                )),
            ))
        })
    }

    pub(super) fn finish_delete(&self, marker: &PendingDelete) -> Result<()> {
        self.with_lock(|| {
            let path = self.pending_delete_path(
                &marker.sandbox_id,
                &marker.namespace,
                &marker.sandbox_cr_uid,
            );
            if !path.exists() {
                return Ok(());
            }
            if self.read_pending_delete(&path)? != *marker {
                return Err(StoreError::Conflict);
            }
            let environment = self.workload_environment(&marker.namespace, &marker.sandbox_cr_uid);
            if environment.try_exists()? {
                let record: WorkloadEnvironment =
                    serde_json::from_slice(&read_private(&environment)?)?;
                if record.sandbox_id != marker.sandbox_id
                    || record.namespace != marker.namespace
                    || record.sandbox_cr_uid != marker.sandbox_cr_uid
                {
                    return Err(StoreError::Conflict);
                }
                fs::remove_file(&environment)?;
                sync_dir(environment.parent().unwrap())?;
            }
            let attempt = self.state.join("active-attempts").join(format!(
                "{}.json",
                workspace_hash(&marker.namespace, &marker.sandbox_cr_uid)
            ));
            if attempt.try_exists()? {
                fs::remove_file(&attempt)?;
                sync_dir(attempt.parent().unwrap())?;
            }
            let revoke = self.state.join("pending-revocations").join(format!(
                "{}.json",
                workspace_hash(&marker.namespace, &marker.sandbox_cr_uid)
            ));
            if revoke.try_exists()? {
                fs::remove_file(&revoke)?;
                sync_dir(revoke.parent().unwrap())?;
            }
            let launch = self.launch_path(&marker.namespace, &marker.sandbox_cr_uid);
            if launch.try_exists()? {
                fs::remove_file(&launch)?;
                sync_dir(launch.parent().unwrap())?;
            }
            fs::remove_file(&path)?;
            sync_dir(&self.state.join("pending-deletes"))?;
            let owner = self.workspace_owner(
                &marker.sandbox_id,
                &workspace_hash(&marker.namespace, &marker.sandbox_cr_uid),
            );
            if owner.exists() {
                fs::remove_file(&owner)?;
                sync_dir(&self.state.join("workspace-owners"))?;
            }
            Ok(())
        })
    }

    /// Record the PVC that will be opened with this workspace key before
    /// authorizing it. PV and cloud disk IDs may be filled after binding.
    /// Retained journal entries prevent a recreated CR from silently using a
    /// fresh key for an existing encrypted volume.
    pub(super) fn record_workspace_volume(
        &self,
        namespace: &str,
        sandbox_cr_uid: &str,
        pvc_name: &str,
        pv_uid_or_name: Option<&str>,
        cloud_disk_id: Option<&str>,
    ) -> Result<()> {
        validate_workspace_identity(namespace, sandbox_cr_uid)?;
        validate_volume_id(pvc_name)?;
        if let Some(value) = pv_uid_or_name {
            validate_volume_id(value)?;
        }
        if let Some(value) = cloud_disk_id {
            validate_volume_id(value)?;
        }
        let id = workspace_hash(namespace, sandbox_cr_uid);
        self.with_lock(|| {
            for item in fs::read_dir(self.state.join("pending-deletes"))? {
                let pending = self.read_pending_delete(&item?.path())?;
                if pending.namespace == namespace && pending.sandbox_cr_uid == sandbox_cr_uid {
                    return Err(StoreError::Revoked);
                }
            }
            for item in fs::read_dir(self.state.join("workspace-journal"))? {
                let path = item?.path();
                let existing: WorkspaceVolumeJournal =
                    serde_json::from_slice(&read_regular(&path)?)?;
                if existing.identity_sha256 == id {
                    continue;
                }
                // PVC names can be reused after deletion. Preserve the
                // physical volume bindings across CR identities instead.
                for volume in existing.volumes {
                    if pv_uid_or_name
                        .is_some_and(|value| volume.pv_uid_or_name.as_deref() == Some(value))
                        || cloud_disk_id
                            .is_some_and(|value| volume.cloud_disk_id.as_deref() == Some(value))
                    {
                        return Err(StoreError::Conflict);
                    }
                }
            }
            let path = self.workspace_journal(&id);
            let mut journal = if path.exists() {
                let prior: WorkspaceVolumeJournal = serde_json::from_slice(&read_regular(&path)?)?;
                if prior.namespace != namespace
                    || prior.sandbox_cr_uid != sandbox_cr_uid
                    || prior.identity_sha256 != id
                {
                    return Err(StoreError::Conflict);
                }
                prior
            } else {
                WorkspaceVolumeJournal {
                    namespace: namespace.to_owned(),
                    sandbox_cr_uid: sandbox_cr_uid.to_owned(),
                    identity_sha256: id.clone(),
                    volumes: Vec::new(),
                }
            };
            if let Some(volume) = journal
                .volumes
                .iter_mut()
                .find(|volume| volume.pvc_name == pvc_name)
            {
                merge_volume_id(&mut volume.pv_uid_or_name, pv_uid_or_name)?;
                merge_volume_id(&mut volume.cloud_disk_id, cloud_disk_id)?;
            } else {
                journal.volumes.push(WorkspaceVolume {
                    pvc_name: pvc_name.to_owned(),
                    pv_uid_or_name: pv_uid_or_name.map(str::to_owned),
                    cloud_disk_id: cloud_disk_id.map(str::to_owned),
                });
            }
            atomic_replace(&path, &serde_json::to_vec(&journal)?)
        })
    }

    /// Exact cloud disk IDs recorded before final measured initdata is released.
    /// An empty result keeps provisional gated initdata unready until all PVCs bind.
    pub(super) fn workspace_disk_ids(
        &self,
        namespace: &str,
        sandbox_cr_uid: &str,
    ) -> Result<Vec<String>> {
        validate_workspace_identity(namespace, sandbox_cr_uid)?;
        let id = workspace_hash(namespace, sandbox_cr_uid);
        self.with_lock(|| {
            let path = self.workspace_journal(&id);
            if !path.exists() {
                return Ok(Vec::new());
            }
            let journal: WorkspaceVolumeJournal = serde_json::from_slice(&read_private(&path)?)?;
            if journal.namespace != namespace
                || journal.sandbox_cr_uid != sandbox_cr_uid
                || journal.identity_sha256 != id
            {
                return Err(StoreError::Conflict);
            }
            let mut disks = std::collections::BTreeSet::new();
            for volume in journal.volumes {
                let Some(disk_id) = volume.cloud_disk_id else {
                    return Ok(Vec::new());
                };
                validate_volume_id(&disk_id)?;
                disks.insert(disk_id);
            }
            Ok(disks.into_iter().collect())
        })
    }

    /// Bind guest mounts to the launch retained on T and its resolved PVCs.
    pub(super) fn workspace_mounts(
        &self,
        sandbox_id: &str,
        namespace: &str,
        uid: &str,
    ) -> Result<serde_json::Value> {
        let launch = self.load_launch(sandbox_id, namespace, uid)?;
        let journal: WorkspaceVolumeJournal = self.with_lock(|| {
            Ok(serde_json::from_slice(&read_private(
                &self.workspace_journal(&workspace_hash(namespace, uid)),
            )?)?)
        })?;
        let spec = launch
            .workload
            .spec
            .as_ref()
            .expect("trusted workload spec");
        let group = spec
            .security_context
            .as_ref()
            .and_then(|s| s.fs_group)
            .map(|g| g.to_string())
            .unwrap_or_default();
        let claims: std::collections::BTreeMap<_, _> = spec
            .volumes
            .iter()
            .flatten()
            .filter_map(|v| v.persistent_volume_claim.as_ref().map(|p| (&v.name, p)))
            .collect();
        let mut mounts = serde_json::Map::new();
        for container in spec
            .containers
            .iter()
            .chain(spec.init_containers.iter().flatten())
        {
            let mut entries = Vec::new();
            for mount in container.volume_mounts.iter().flatten() {
                let Some(claim) = claims.get(&mount.name) else {
                    continue;
                };
                let disk = journal
                    .volumes
                    .iter()
                    .find(|v| v.pvc_name == claim.claim_name)
                    .and_then(|v| v.cloud_disk_id.as_ref())
                    .ok_or(StoreError::Invalid("workspace PVC has no bound disk"))?;
                let readonly = mount.read_only.unwrap_or(false) || claim.read_only.unwrap_or(false);
                entries.push(serde_json::json!({
                    "mount_point": mount.mount_path, "disk_id": disk,
                    "readonly": readonly, "fs_group": group,
                    "options": if readonly { vec!["ro"] } else { Vec::<&str>::new() },
                }));
            }
            mounts.insert(container.name.clone(), serde_json::Value::Array(entries));
        }
        Ok(serde_json::Value::Object(mounts))
    }

    /// Preserve one 32-byte key across workload attempts and generations.
    /// The previous serving path is withdrawn before a new measured workload
    /// binding becomes active. The key itself remains in private host state.
    #[cfg(test)]
    pub(super) fn ensure_workspace_key(
        &self,
        namespace: &str,
        sandbox_cr_uid: &str,
        workload_initdata_sha384: &str,
    ) -> Result<PlannedSecret> {
        self.authorize_workspace_key(namespace, sandbox_cr_uid, workload_initdata_sha384, None)
    }

    pub(super) fn ensure_workspace_key_for_attempt(
        &self,
        namespace: &str,
        uid: &str,
        digest: &str,
        attempt: &str,
    ) -> Result<PlannedSecret> {
        self.authorize_workspace_key(namespace, uid, digest, Some(attempt))
    }

    fn authorize_workspace_key(
        &self,
        namespace: &str,
        sandbox_cr_uid: &str,
        workload_initdata_sha384: &str,
        attempt: Option<&str>,
    ) -> Result<PlannedSecret> {
        validate_workspace_identity(namespace, sandbox_cr_uid)?;
        validate_digest(workload_initdata_sha384)?;
        if self.policy.is_none() {
            return Err(StoreError::Policy);
        }
        let planned = self.plan_workspace_key(namespace, sandbox_cr_uid)?;
        let id = workspace_hash(namespace, sandbox_cr_uid);
        self.with_lock(|| {
            if self.revoking(&format!("workspace-{id}")).exists() {
                return Err(StoreError::Revoked);
            }
            if let Some(expected) = attempt {
                let record: ActiveAttempt = serde_json::from_slice(&read_private(
                    &self
                        .state
                        .join("active-attempts")
                        .join(format!("{id}.json")),
                )?)?;
                if record.attempt != expected
                    || record.sandbox_cr_uid != sandbox_cr_uid
                    || self
                        .state
                        .join("pending-revocations")
                        .join(format!("{id}.json"))
                        .exists()
                    || self
                        .tombstone(&identity_hash(
                            BootstrapRole::Workload,
                            &record.generation,
                            &record.sandbox_id,
                            &record.attempt,
                        ))
                        .exists()
                {
                    return Err(StoreError::Revoked);
                }
            }

            for item in fs::read_dir(self.state.join("pending-deletes"))? {
                let pending = self.read_pending_delete(&item?.path())?;
                if pending.namespace == namespace && pending.sandbox_cr_uid == sandbox_cr_uid {
                    return Err(StoreError::Revoked);
                }
            }
            if !self.has_workspace_owner(namespace, sandbox_cr_uid, &id)? {
                return Err(StoreError::Invalid("workspace owner not recorded"));
            }
            let journal: WorkspaceVolumeJournal =
                serde_json::from_slice(&read_regular(&self.workspace_journal(&id))?)?;
            if journal.namespace != namespace
                || journal.sandbox_cr_uid != sandbox_cr_uid
                || journal.identity_sha256 != id
                || journal.volumes.is_empty()
            {
                return Err(StoreError::Conflict);
            }
            let private = self.workspace_key(&id);
            if !private.exists() {
                let mut key = [0u8; 32];
                SystemRandom::new()
                    .fill(&mut key)
                    .map_err(|_| StoreError::Crypto)?;
                atomic_new(&private, &key)?;
            }
            let key = read_private(&private)?;
            if key.len() != 32 {
                return Err(StoreError::Conflict);
            }
            let binding = WorkspaceBinding {
                resource_path: planned.resource_path.clone(),
                initdata_sha384: workload_initdata_sha384.to_owned(),
                namespace: namespace.to_owned(),
                sandbox_cr_uid: sandbox_cr_uid.to_owned(),
                resource_sha256: hex::encode(Sha256::digest(&key)),
                identity_sha256: id.clone(),
            };
            let binding_path = self.workspace_binding(&id);
            let serving = self.workspace_resource(&id);
            let served = if serving.exists() {
                if read_regular(&serving)? != key {
                    return Err(StoreError::Conflict);
                }
                true
            } else {
                false
            };
            let new_binding = !binding_path.exists();
            if !new_binding {
                let previous: WorkspaceBinding =
                    serde_json::from_slice(&read_regular(&binding_path)?)?;
                if previous == binding && served {
                    return Ok(());
                }
            }
            if served {
                fs::remove_file(&serving)?;
                sync_dir(serving.parent().unwrap())?;
            }
            atomic_replace(&binding_path, &serde_json::to_vec(&binding)?)?;
            let operation = (|| {
                atomic_new(&serving, &key)?;
                self.refresh_policy()?;
                Ok(())
            })();
            if operation.is_err() {
                self.withdraw_failed_publication(&binding_path, &serving)?;
            }
            operation
        })?;
        Ok(planned)
    }

    /// Withdraw access immediately, retaining the private 32-byte key for
    /// restart with the same PVC.
    pub(super) fn deauthorize_workspace_key(
        &self,
        namespace: &str,
        sandbox_cr_uid: &str,
    ) -> Result<()> {
        validate_workspace_identity(namespace, sandbox_cr_uid)?;
        if self.policy.is_none() {
            return Err(StoreError::Policy);
        }
        let id = workspace_hash(namespace, sandbox_cr_uid);
        self.with_lock(|| self.deauthorize_workspace_identity(&id))
    }

    /// Publish one original Kubernetes Secret data value. A retry with the
    /// same identity, key, measurement and bytes is idempotent; changed input
    /// is rejected. The binding is durable before the resource is exposed.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn publish_file(
        &self,
        role: BootstrapRole,
        generation: &str,
        sandbox_id: &str,
        sandbox_cr_uid: &str,
        attempt_id: &str,
        key: &str,
        plaintext: &[u8],
        expected_initdata_sha384: &str,
    ) -> Result<PublishedSecret> {
        validate(
            role,
            generation,
            sandbox_id,
            attempt_id,
            Some(key),
            Some(expected_initdata_sha384),
        )?;
        validate_workspace_identity("bootstrap", sandbox_cr_uid)?;
        if self.policy.is_none() {
            return Err(StoreError::Policy);
        }
        let identity = identity_hash(role, generation, sandbox_id, attempt_id);
        let id = file_hash(&identity, key);
        let planned = self.plan_file(role, generation, sandbox_id, attempt_id, key)?;
        let uri = planned.resource_uri;
        let resource_path = planned.resource_path;
        let resource = self.resource(&id);
        let binding_path = self.binding(&id);
        let digest = hex::encode(Sha256::digest(plaintext));
        let binding = Binding {
            resource_path,
            initdata_sha384: expected_initdata_sha384.to_owned(),
            role: role.as_str().to_owned(),
            generation: generation.to_owned(),
            sandbox_id: sandbox_id.to_owned(),
            sandbox_cr_uid: sandbox_cr_uid.to_owned(),
            attempt_id: attempt_id.to_owned(),
            key: key.to_owned(),
            resource_sha256: digest.clone(),
            identity_sha256: identity.clone(),
        };
        let input = descriptor_input(&uri)?;
        let sealed_descriptor = self.with_lock(|| {
            if self.has_pending_delete_for_sandbox(sandbox_id)? {
                return Err(StoreError::Revoked);
            }
            if self.tombstone(&identity).exists()
                || self.revoking(&identity).exists()
                || self.quarantine(&id).exists()
            {
                return Err(StoreError::Revoked);
            }
            let new_binding = !binding_path.exists();
            if new_binding {
                atomic_new(&binding_path, &serde_json::to_vec(&binding)?)?;
            } else {
                let prior: Binding = serde_json::from_slice(&read_regular(&binding_path)?)?;
                if prior != binding {
                    return Err(StoreError::Conflict);
                }
            }
            let was_unserved = !resource.exists();
            let operation = (|| {
                let descriptor = self.load_or_sign_descriptor(&id, &input)?;
                if resource.exists() {
                    if hex::encode(Sha256::digest(read_regular(&resource)?)) != digest {
                        return Err(StoreError::Conflict);
                    }
                } else {
                    atomic_new(&resource, plaintext)?;
                }
                self.refresh_policy()?;
                Ok(descriptor)
            })();
            if operation.is_err() && (was_unserved || new_binding) {
                self.withdraw_failed_publication(&binding_path, &resource)?;
            }
            operation
        })?;
        Ok(PublishedSecret {
            sealed_descriptor,
            #[cfg(test)]
            resource_uri: uri,
            #[cfg(test)]
            resource_path: binding.resource_path,
            #[cfg(test)]
            binding_path,
        })
    }

    fn load_or_sign_descriptor(&self, id: &str, input: &str) -> Result<String> {
        let descriptor_path = self.descriptor(id);
        let pair = self.load_or_create_signer()?;
        if descriptor_path.exists() {
            let existing = String::from_utf8(read_regular(&descriptor_path)?)
                .map_err(|_| StoreError::Invalid("stored descriptor encoding"))?;
            let signature = existing
                .strip_prefix(&format!("sealed.{input}."))
                .ok_or(StoreError::Conflict)?;
            let signature = URL_SAFE_NO_PAD
                .decode(signature)
                .map_err(|_| StoreError::Conflict)?;
            UnparsedPublicKey::new(&ECDSA_P256_SHA256_FIXED, pair.public_key().as_ref())
                .verify(input.as_bytes(), &signature)
                .map_err(|_| StoreError::Conflict)?;
            Ok(existing)
        } else {
            let signature = pair
                .sign(&SystemRandom::new(), input.as_bytes())
                .map_err(|_| StoreError::Crypto)?;
            let created = format!(
                "sealed.{input}.{}",
                URL_SAFE_NO_PAD.encode(signature.as_ref())
            );
            atomic_new(&descriptor_path, created.as_bytes())?;
            Ok(created)
        }
    }

    /// Remove every file for an identity. Resource rename is the serving cut
    /// before a tombstone is committed. Interrupted revocations are detected
    /// through quarantine files; a later retry finishes the operation.
    #[cfg(test)]
    pub(super) fn revoke_attempt(
        &self,
        role: BootstrapRole,
        generation: &str,
        sandbox_id: &str,
        attempt_id: &str,
    ) -> Result<()> {
        validate(role, generation, sandbox_id, attempt_id, None, None)?;
        if self.policy.is_none() {
            return Err(StoreError::Policy);
        }
        let identity = identity_hash(role, generation, sandbox_id, attempt_id);
        self.with_lock(|| self.revoke_identities([identity]))
    }

    /// Withdraw a CR's bootstrap identities without touching a replacement
    /// CR that reused the Sandbox ID.
    pub(super) fn revoke_sandbox_uid(&self, sandbox_id: &str, sandbox_cr_uid: &str) -> Result<()> {
        validate_sandbox(sandbox_id)?;
        validate_workspace_identity("bootstrap", sandbox_cr_uid)?;
        if self.policy.is_none() {
            return Err(StoreError::Policy);
        }
        self.with_lock(|| {
            let mut identities = std::collections::BTreeSet::new();
            for item in fs::read_dir(self.state.join("bindings"))? {
                let record: Binding = serde_json::from_slice(&read_regular(&item?.path())?)?;
                if record.sandbox_id == sandbox_id && record.sandbox_cr_uid == sandbox_cr_uid {
                    identities.insert(record.identity_sha256);
                }
            }
            // Include attempts that have not published a binding yet. A late
            // publisher must encounter a tombstone, not resurrect a stopped VM.
            for item in fs::read_dir(self.state.join("active-attempts"))? {
                let attempt: ActiveAttempt = serde_json::from_slice(&read_private(&item?.path())?)?;
                if attempt.sandbox_id == sandbox_id && attempt.sandbox_cr_uid == sandbox_cr_uid {
                    for role in [BootstrapRole::Workload, BootstrapRole::Supervisor] {
                        identities.insert(identity_hash(
                            role,
                            &attempt.generation,
                            sandbox_id,
                            &attempt.attempt,
                        ));
                    }
                }
            }
            self.revoke_identities(identities)
        })
    }

    // Stage every serving cut before publishing one policy update. Keep each
    // existing revocation marker until that update succeeds, including retries
    // after the bindings themselves have already been removed.
    fn revoke_identities(&self, identities: impl IntoIterator<Item = String>) -> Result<()> {
        let mut identities: std::collections::BTreeSet<_> = identities.into_iter().collect();
        for item in fs::read_dir(self.state.join("revoking"))? {
            let name = item?
                .file_name()
                .into_string()
                .map_err(|_| StoreError::UnsafePath)?;
            let digest = name.strip_prefix("workspace-").unwrap_or(&name);
            if digest.len() != 64
                || !digest
                    .bytes()
                    .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
            {
                return Err(StoreError::UnsafePath);
            }
            identities.insert(name);
        }
        let mut completed = Vec::new();
        let mut errors = Vec::new();
        for identity in identities {
            match self.stage_identity_revocation(&identity) {
                Ok(true) => completed.push(identity),
                Ok(false) => {}
                Err(error) => errors.push(error.to_string()),
            }
        }
        if !completed.is_empty() {
            match self.refresh_policy() {
                Ok(()) => {
                    for identity in completed {
                        fs::remove_file(self.revoking(&identity))?;
                    }
                    sync_dir(&self.state.join("revoking"))?;
                }
                Err(error) => errors.push(error.to_string()),
            }
        }
        if errors.is_empty() {
            Ok(())
        } else {
            Err(StoreError::Cleanup(errors.join("; ")))
        }
    }

    fn stage_identity_revocation(&self, identity: &str) -> Result<bool> {
        if let Some(id) = identity.strip_prefix("workspace-") {
            let serving = self.workspace_resource(id);
            let binding = self.workspace_binding(id);
            let marker = self.revoking(identity);
            if !serving.exists() && !binding.exists() && !marker.exists() {
                return Ok(false);
            }
            if !marker.exists() {
                atomic_new(&marker, b"revoking\n")?;
            }
            for path in [serving, binding] {
                if path.exists() {
                    fs::remove_file(&path)?;
                    sync_dir(path.parent().unwrap())?;
                }
            }
            return Ok(true);
        }
        if self.tombstone(identity).exists() && !self.revoking(identity).exists() {
            return Ok(false);
        }
        let revoking = self.revoking(identity);
        if !revoking.exists() {
            atomic_new(&revoking, b"revoking\n")?;
        }
        let mut entries = Vec::new();
        for item in fs::read_dir(self.state.join("bindings"))? {
            let path = item?.path();
            let record: Binding = serde_json::from_slice(&read_regular(&path)?)?;
            if record.identity_sha256 == identity {
                let id = path
                    .file_stem()
                    .and_then(|s| s.to_str())
                    .ok_or(StoreError::UnsafePath)?;
                if record.resource_path != format!("resource/default/bootstrap/{id}") {
                    return Err(StoreError::Conflict);
                }
                entries.push((id.to_owned(), path));
            }
        }
        for (id, _) in &entries {
            let serving = self.resource(id);
            let quarantine = self.quarantine(id);
            if serving.exists() {
                if quarantine.exists() {
                    return Err(StoreError::Conflict);
                }
                fs::rename(&serving, &quarantine)?;
                sync_dir(serving.parent().unwrap())?;
            }
        }
        let tombstone = self.tombstone(identity);
        if !tombstone.exists() {
            atomic_new(&tombstone, b"revoked\n")?;
        }
        for (id, binding) in entries {
            let quarantine = self.quarantine(&id);
            if quarantine.exists() {
                fs::remove_file(&quarantine)?;
            }
            let descriptor = self.descriptor(&id);
            if descriptor.exists() {
                fs::remove_file(&descriptor)?;
            }
            if binding.exists() {
                fs::remove_file(&binding)?;
            }
        }
        sync_dir(&self.repository)?;
        sync_dir(&self.state.join("bindings"))?;
        sync_dir(&self.state.join("descriptors"))?;
        Ok(true)
    }

    pub(super) fn binding_directory(&self) -> PathBuf {
        self.state.join("bindings")
    }
    pub(super) fn workspace_binding_directory(&self) -> PathBuf {
        self.state.join("workspace-bindings")
    }

    fn resource(&self, id: &str) -> PathBuf {
        self.repository
            .join(staged_resource_key(&format!("default/bootstrap/{id}")))
    }
    fn quarantine(&self, id: &str) -> PathBuf {
        self.repository.join(format!(".revoking-{id}"))
    }
    fn binding(&self, id: &str) -> PathBuf {
        self.state.join("bindings").join(format!("{id}.json"))
    }
    fn descriptor(&self, id: &str) -> PathBuf {
        self.state.join("descriptors").join(id)
    }
    fn tombstone(&self, identity: &str) -> PathBuf {
        self.state.join("revoked").join(identity)
    }
    fn revoking(&self, identity: &str) -> PathBuf {
        self.state.join("revoking").join(identity)
    }
    fn workspace_key(&self, identity: &str) -> PathBuf {
        self.state.join("workspace-keys").join(identity)
    }
    fn workload_environment(&self, namespace: &str, uid: &str) -> PathBuf {
        self.state
            .join("workload-environments")
            .join(format!("{}.json", workspace_hash(namespace, uid)))
    }
    fn workspace_binding(&self, identity: &str) -> PathBuf {
        self.state
            .join("workspace-bindings")
            .join(format!("{identity}.json"))
    }
    fn workspace_resource(&self, identity: &str) -> PathBuf {
        self.repository.join(staged_resource_key(&format!(
            "default/workspace/{identity}"
        )))
    }
    fn workspace_journal(&self, identity: &str) -> PathBuf {
        self.state
            .join("workspace-journal")
            .join(format!("{identity}.json"))
    }
    fn workspace_owner(&self, sandbox_id: &str, identity: &str) -> PathBuf {
        self.state
            .join("workspace-owners")
            .join(format!("{}-{identity}.json", sandbox_hash(sandbox_id)))
    }

    fn pending_delete_path(&self, sandbox_id: &str, namespace: &str, uid: &str) -> PathBuf {
        let mut hash = Sha256::new();
        hash.update(b"openshell-pending-delete-v1\0");
        hash.update(sandbox_id);
        hash.update([0]);
        hash.update(namespace);
        hash.update([0]);
        hash.update(uid);
        self.state
            .join("pending-deletes")
            .join(format!("{}.json", hex::encode(hash.finalize())))
    }

    fn read_pending_delete(&self, path: &Path) -> Result<PendingDelete> {
        let marker: PendingDelete = serde_json::from_slice(&read_regular(path)?)?;
        validate_sandbox(&marker.sandbox_id)?;
        validate_workspace_identity(&marker.namespace, &marker.sandbox_cr_uid)?;
        if path
            != self.pending_delete_path(
                &marker.sandbox_id,
                &marker.namespace,
                &marker.sandbox_cr_uid,
            )
        {
            return Err(StoreError::Conflict);
        }
        if marker.bootstrap_identities.iter().any(|identity| {
            identity.len() != 64
                || !identity
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        }) {
            return Err(StoreError::Conflict);
        }
        Ok(marker)
    }

    fn has_pending_delete_for_sandbox(&self, sandbox_id: &str) -> Result<bool> {
        for item in fs::read_dir(self.state.join("pending-deletes"))? {
            if self.read_pending_delete(&item?.path())?.sandbox_id == sandbox_id {
                return Ok(true);
            }
        }
        Ok(false)
    }

    fn has_workspace_owner(&self, namespace: &str, uid: &str, id: &str) -> Result<bool> {
        for item in fs::read_dir(self.state.join("workspace-owners"))? {
            let owner = self.read_workspace_owner(&item?.path())?;
            if owner.namespace == namespace
                && owner.sandbox_cr_uid == uid
                && owner.workspace_identity_sha256 == id
            {
                return Ok(true);
            }
        }
        Ok(false)
    }

    fn read_workspace_owner(&self, path: &Path) -> Result<WorkspaceOwner> {
        let owner: WorkspaceOwner = serde_json::from_slice(&read_private(path)?)?;
        validate_sandbox(&owner.sandbox_id)?;
        validate_workspace_identity(&owner.namespace, &owner.sandbox_cr_uid)?;
        if owner.workspace_identity_sha256
            != workspace_hash(&owner.namespace, &owner.sandbox_cr_uid)
            || path != self.workspace_owner(&owner.sandbox_id, &owner.workspace_identity_sha256)
        {
            return Err(StoreError::Conflict);
        }
        Ok(owner)
    }

    fn deauthorize_workspace_identity(&self, id: &str) -> Result<()> {
        self.revoke_identities([format!("workspace-{id}")])
    }

    fn withdraw_failed_publication(&self, binding: &Path, serving: &Path) -> Result<()> {
        if serving.exists() {
            fs::remove_file(serving)?;
            sync_dir(serving.parent().unwrap())?;
        }
        if binding.exists() {
            fs::remove_file(binding)?;
            sync_dir(binding.parent().unwrap())?;
        }
        self.refresh_policy()
    }

    fn refresh_policy(&self) -> Result<()> {
        self.refresh_policy_with_timeout(PUBLICATION_TIMEOUT)
    }

    fn refresh_policy_with_timeout(&self, timeout: std::time::Duration) -> Result<()> {
        let (script, output, as_output) = self.policy.as_ref().ok_or(StoreError::Policy)?;
        // GNU timeout terminates the renderer and its children, and reaps the
        // process even if it ignores TERM. Coreutils is part of the Ubuntu host.
        let mut command = Command::new("timeout");
        command
            .arg("--kill-after=5s")
            .arg(format!("{}s", timeout.as_secs_f64()))
            .arg("python3")
            .arg(script)
            .arg("--bindings-dir")
            .arg(self.binding_directory())
            .arg("--workspace-bindings-dir")
            .arg(self.workspace_binding_directory())
            .arg("--as-policy-output")
            .arg(as_output)
            .arg("--output")
            .arg(output);
        if let Some(config) = &self.trustee_config {
            command
                .arg("--trustee-config")
                .arg(config)
                .arg("--resources-dir")
                .arg(&self.repository)
                .arg("--publication-journal")
                .arg(self.state.join("trustee-publication.json"));
        }
        let result = command.output()?;
        if result.status.success() {
            Ok(())
        } else if result.status.code() == Some(124) || result.status.code() == Some(137) {
            Err(StoreError::Publication(
                "policy refresh timed out".to_owned(),
            ))
        } else if self.trustee_config.is_some() {
            Err(StoreError::Publication(
                String::from_utf8_lossy(&result.stderr)
                    .lines()
                    .last()
                    .unwrap_or("management client failed")
                    .chars()
                    .take(600)
                    .collect(),
            ))
        } else {
            Err(StoreError::Policy)
        }
    }

    fn with_lock<T>(&self, op: impl FnOnce() -> Result<T>) -> Result<T> {
        let operation = || {
            let lock = OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(false)
                .mode(0o600)
                .open(self.state.join(".lock"))?;
            let deadline = std::time::Instant::now() + PUBLICATION_TIMEOUT;
            loop {
                match lock.try_lock_exclusive() {
                    Ok(()) => break,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        if std::time::Instant::now() >= deadline {
                            return Err(StoreError::Publication(
                                "bootstrap store lock timed out".to_owned(),
                            ));
                        }
                        std::thread::sleep(std::time::Duration::from_millis(25));
                    }
                    Err(error) => return Err(error.into()),
                }
            }
            let result = op();
            FileExt::unlock(&lock)?;
            result
        };
        // Filesystem transactions and bounded API publication must not occupy
        // a Tokio worker while waiting for flock or a management response.
        if tokio::runtime::Handle::try_current().is_ok_and(|handle| {
            handle.runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread
        }) {
            tokio::task::block_in_place(operation)
        } else {
            operation()
        }
    }

    fn clean_temporary_files(&self) -> Result<()> {
        for dir in [
            self.state.clone(),
            self.state.join("bindings"),
            self.state.join("descriptors"),
            self.state.join("revoked"),
            self.state.join("revoking"),
            self.state.join("workspace-keys"),
            self.state.join("workspace-bindings"),
            self.state.join("workspace-journal"),
            self.state.join("workspace-owners"),
            self.state.join("pending-deletes"),
            self.state.join("workload-environments"),
            self.state.join("launch-intents"),
            self.state.join("active-attempts"),
            self.state.join("pending-revocations"),
            self.repository.clone(),
        ] {
            let mut changed = false;
            for item in fs::read_dir(&dir)? {
                let path = item?.path();
                if path
                    .file_name()
                    .and_then(|s| s.to_str())
                    .is_some_and(|name| name.starts_with(".tmp-"))
                {
                    if !fs::symlink_metadata(&path)?.file_type().is_file() {
                        return Err(StoreError::UnsafePath);
                    }
                    fs::remove_file(&path)?;
                    changed = true;
                }
            }
            if changed {
                sync_dir(&dir)?;
            }
        }
        Ok(())
    }

    fn load_or_create_signer(&self) -> Result<EcdsaKeyPair> {
        if !self.signing_key.exists() {
            let rng = SystemRandom::new();
            let key = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng)
                .map_err(|_| StoreError::Crypto)?;
            atomic_new(&self.signing_key, key.as_ref())?;
        }
        let bytes = read_private(&self.signing_key)?;
        EcdsaKeyPair::from_pkcs8(
            &ECDSA_P256_SHA256_FIXED_SIGNING,
            &bytes,
            &SystemRandom::new(),
        )
        .map_err(|_| StoreError::Crypto)
    }

    fn publish_signer(&self, pair: &EcdsaKeyPair) -> Result<()> {
        let point = pair.public_key().as_ref();
        if point.len() != 65 || point[0] != 4 {
            return Err(StoreError::Crypto);
        }
        let jwk = serde_json::json!({"kty":"EC", "crv":"P-256", "alg":"ES256", "use":"sig",
            "x":URL_SAFE_NO_PAD.encode(&point[1..33]), "y":URL_SAFE_NO_PAD.encode(&point[33..65])});
        let bytes = serde_json::to_vec(&jwk)?;
        let path = self
            .repository
            .join(staged_resource_key("default/bootstrap-signer/key"));
        if path.exists() {
            if read_regular(&path)? != bytes {
                return Err(StoreError::Conflict);
            }
        } else {
            atomic_new(&path, &bytes)?;
        }
        Ok(())
    }
}

/// Private staging names; these are not Trustee storage-backend filenames.
/// The caller supplies a canonical resource key; URI and binding formats stay unchanged.
pub fn staged_resource_key(resource_key: &str) -> String {
    resource_key
        .strip_prefix("default/")
        .expect("owned resource namespace")
        .replace('/', "-")
}

fn validate(
    _role: BootstrapRole,
    generation: &str,
    sandbox: &str,
    attempt: &str,
    key: Option<&str>,
    digest: Option<&str>,
) -> Result<()> {
    validate_generation(generation)?;
    validate_attempt(attempt)?;
    validate_sandbox(sandbox)?;
    if let Some(key) = key
        && (key.is_empty()
            || key.len() > 253
            || !key
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_')))
    {
        return Err(StoreError::Invalid("Secret data key"));
    }
    if let Some(digest) = digest {
        validate_digest(digest)?;
    }
    Ok(())
}
fn validate_generation(generation: &str) -> Result<()> {
    if generation.is_empty()
        || generation.len() > 64
        || !generation
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
    {
        return Err(StoreError::Invalid("generation must match [a-z0-9-]{1,64}"));
    }
    Ok(())
}
fn validate_attempt(attempt: &str) -> Result<()> {
    if attempt.len() != 64
        || !attempt
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    {
        return Err(StoreError::Invalid("attempt must be lowercase 64 hex"));
    }
    Ok(())
}
fn validate_sandbox(sandbox: &str) -> Result<()> {
    if sandbox.is_empty()
        || sandbox.len() > 128
        || !sandbox
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        return Err(StoreError::Invalid("sandbox_id"));
    }
    Ok(())
}
fn validate_digest(digest: &str) -> Result<()> {
    if digest.len() != 96
        || !digest
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    {
        return Err(StoreError::Invalid("initdata SHA-384 digest"));
    }
    Ok(())
}
fn validate_workspace_identity(namespace: &str, uid: &str) -> Result<()> {
    for value in [namespace, uid] {
        if value.is_empty()
            || value.len() > 253
            || !value
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        {
            return Err(StoreError::Invalid("workspace namespace or CR UID"));
        }
    }
    Ok(())
}
fn validate_volume_id(value: &str) -> Result<()> {
    if value.is_empty() || value.len() > 512 || !value.bytes().all(|b| b.is_ascii_graphic()) {
        return Err(StoreError::Invalid("PVC, PV or cloud disk ID"));
    }
    Ok(())
}
fn merge_volume_id(stored: &mut Option<String>, candidate: Option<&str>) -> Result<()> {
    if let Some(candidate) = candidate {
        if stored
            .as_deref()
            .is_some_and(|existing| existing != candidate)
        {
            return Err(StoreError::Conflict);
        }
        *stored = Some(candidate.to_owned());
    }
    Ok(())
}

fn identity_hash(role: BootstrapRole, generation: &str, sandbox: &str, attempt: &str) -> String {
    let mut h = Sha256::new();
    h.update(b"openshell-bootstrap-identity-v1\0");
    h.update(role.as_str());
    h.update([0]);
    h.update(generation);
    h.update([0]);
    h.update(sandbox);
    h.update([0]);
    h.update(attempt);
    hex::encode(h.finalize())
}
fn file_hash(identity: &str, key: &str) -> String {
    let mut h = Sha256::new();
    h.update(b"openshell-bootstrap-file-v1\0");
    h.update(identity);
    h.update([0]);
    h.update(key);
    hex::encode(h.finalize())
}
fn descriptor_input(uri: &str) -> Result<String> {
    let payload = serde_json::json!({
        "version":"0.1.0", "type":"vault", "name":uri,
        "provider":"kbs", "provider_settings":{}, "annotations":{}
    });
    let header = serde_json::json!({"alg":"ES256", "kid":SIGNER_URI});
    Ok(format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header)?),
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(&payload)?)
    ))
}
fn workspace_hash(namespace: &str, uid: &str) -> String {
    let mut h = Sha256::new();
    h.update(b"openshell-workspace-v1\0");
    h.update(namespace);
    h.update([0]);
    h.update(uid);
    hex::encode(h.finalize())
}
fn sandbox_hash(sandbox_id: &str) -> String {
    let mut h = Sha256::new();
    h.update(b"openshell-workspace-owner-v1\0");
    h.update(sandbox_id);
    hex::encode(h.finalize())
}
fn ensure_dir(path: &Path) -> Result<()> {
    if path.exists() {
        if !fs::symlink_metadata(path)?.file_type().is_dir() {
            return Err(StoreError::UnsafePath);
        }
    } else {
        fs::create_dir_all(path)?;
    }
    sync_dir(path)?;
    Ok(())
}
fn ensure_private_dir(path: &Path) -> Result<()> {
    let existed = path.exists();
    ensure_dir(path)?;
    if !existed {
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    if fs::metadata(path)?.permissions().mode() & 0o077 != 0 {
        return Err(StoreError::UnsafePath);
    }
    Ok(())
}
fn read_regular(path: &Path) -> Result<Vec<u8>> {
    if !fs::symlink_metadata(path)?.file_type().is_file() {
        return Err(StoreError::UnsafePath);
    }
    let mut bytes = Vec::new();
    File::open(path)?.read_to_end(&mut bytes)?;
    Ok(bytes)
}
fn read_private(path: &Path) -> Result<Vec<u8>> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_file()
        || metadata.permissions().mode() & 0o077 != 0
        || metadata.nlink() != 1
    {
        return Err(StoreError::UnsafePath);
    }
    read_regular(path)
}
fn sync_dir(path: &Path) -> Result<()> {
    File::open(path)?.sync_all()?;
    Ok(())
}
fn atomic_new(path: &Path, data: &[u8]) -> Result<()> {
    let parent = path.parent().ok_or(StoreError::UnsafePath)?;
    let mut nonce = [0u8; 16];
    SystemRandom::new()
        .fill(&mut nonce)
        .map_err(|_| StoreError::Crypto)?;
    let tmp = parent.join(format!(".tmp-{}", hex::encode(nonce)));
    let result = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&tmp)?;
        file.write_all(data)?;
        file.sync_all()?;
        fs::hard_link(&tmp, path)?;
        sync_dir(parent)?;
        Ok(())
    })();
    let _ = fs::remove_file(&tmp);
    result
}
fn atomic_replace(path: &Path, data: &[u8]) -> Result<()> {
    let parent = path.parent().ok_or(StoreError::UnsafePath)?;
    let mut nonce = [0u8; 16];
    SystemRandom::new()
        .fill(&mut nonce)
        .map_err(|_| StoreError::Crypto)?;
    let tmp = parent.join(format!(".tmp-{}", hex::encode(nonce)));
    let result = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&tmp)?;
        file.write_all(data)?;
        file.sync_all()?;
        if path.exists() && !fs::symlink_metadata(path)?.file_type().is_file() {
            return Err(StoreError::UnsafePath);
        }
        fs::rename(&tmp, path)?;
        sync_dir(parent)?;
        Ok(())
    })();
    let _ = fs::remove_file(&tmp);
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use ring::signature::{ECDSA_P256_SHA256_FIXED, UnparsedPublicKey};
    use tempfile::TempDir;

    const GENERATION: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const RESTART_GENERATION: &str = "g000000000000002a";
    const ATTEMPT: &str = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210";
    const INITDATA: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    fn fixture() -> (TempDir, BootstrapStore) {
        let tmp = tempfile::tempdir().unwrap();
        let renderer = tmp.path().join("renderer.py");
        fs::write(
            &renderer,
            r"import json, pathlib, sys
args = sys.argv
counter = pathlib.Path(__file__).with_name('renderer-calls')
counter.write_text(str(int(counter.read_text()) + 1) if counter.exists() else '1')
if pathlib.Path(__file__).with_name('fail').exists():
    sys.exit(2)
digests = set()
for option in ('--bindings-dir', '--workspace-bindings-dir'):
    for path in pathlib.Path(args[args.index(option) + 1]).glob('*.json'):
        digests.add(json.loads(path.read_text())['initdata_sha384'])
pathlib.Path(args[args.index('--as-policy-output') + 1]).write_text('package policy\napproved_initdata := ' + json.dumps(sorted(digests)) + '\n')
if pathlib.Path(__file__).with_name('fail_after_as').exists():
    sys.exit(3)
pathlib.Path(args[args.index('--output') + 1]).write_text('package policy\ndefault allow = false\n')
",
        )
        .unwrap();
        let store = BootstrapStore::open_with_policies(
            tmp.path().join("repo"),
            tmp.path().join("state/signer.pk8"),
            &renderer,
            tmp.path().join("policy.rego"),
            tmp.path().join("as.rego"),
        )
        .unwrap();
        (tmp, store)
    }

    #[test]
    fn policy_process_deadline_is_enforced() {
        let (tmp, store) = fixture();
        fs::write(
            tmp.path().join("renderer.py"),
            "import time\ntime.sleep(30)\n",
        )
        .unwrap();
        let started = std::time::Instant::now();
        let error = store
            .refresh_policy_with_timeout(std::time::Duration::from_millis(50))
            .unwrap_err();
        assert!(error.to_string().contains("timed out"), "{error}");
        assert!(started.elapsed() < std::time::Duration::from_secs(5));
    }

    #[test]
    fn workspace_revocation_retries_publication_and_skips_completed_work() {
        let (tmp, store) = fixture();
        store
            .record_workspace_owner("sandbox-workspace", "ns", "uid")
            .unwrap();
        store
            .record_workspace_volume("ns", "uid", "pvc", None, None)
            .unwrap();
        store.ensure_workspace_key("ns", "uid", INITDATA).unwrap();
        fs::write(tmp.path().join("fail"), b"fail").unwrap();
        assert!(store.deauthorize_workspace_key("ns", "uid").is_err());
        assert!(
            !store
                .workspace_resource(&workspace_hash("ns", "uid"))
                .exists()
        );
        assert!(matches!(
            store.ensure_workspace_key("ns", "uid", INITDATA),
            Err(StoreError::Revoked)
        ));
        fs::remove_file(tmp.path().join("fail")).unwrap();
        let calls_before: usize = fs::read_to_string(tmp.path().join("renderer-calls"))
            .unwrap()
            .parse()
            .unwrap();
        store.deauthorize_workspace_key("ns", "uid").unwrap();
        store.deauthorize_workspace_key("ns", "uid").unwrap();
        let calls_after: usize = fs::read_to_string(tmp.path().join("renderer-calls"))
            .unwrap()
            .parse()
            .unwrap();
        assert_eq!(calls_after, calls_before + 1);
        store.ensure_workspace_key("ns", "uid", INITDATA).unwrap();
    }

    #[test]
    fn sealed_environment_survives_stop_and_store_restart_without_kubernetes() {
        let (tmp, store) = fixture();
        let environment = std::collections::HashMap::from([
            (
                "TOKEN".to_string(),
                "test-secret=含空格\nsecond line".to_string(),
            ),
            ("EMPTY".to_string(), String::new()),
        ]);
        store
            .record_workload_environment("sandbox-env", "ns", "uid", &environment)
            .unwrap();
        store
            .record_workload_environment("sandbox-env", "ns", "uid", &environment)
            .unwrap();
        let path = store.workload_environment("ns", "uid");
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(
            fs::metadata(path.parent().unwrap())
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
        let bytes = serde_json::to_vec(&serde_json::json!({"child_env": environment})).unwrap();
        let old = store
            .publish_file(
                BootstrapRole::Workload,
                GENERATION,
                "sandbox-env",
                "uid",
                ATTEMPT,
                "boundary.json",
                &bytes,
                INITDATA,
            )
            .unwrap();
        let opaque = old.resource_uri.rsplit('/').next().unwrap();
        assert_eq!(fs::read(store.resource(opaque)).unwrap(), bytes);
        assert!(!old.sealed_descriptor.contains("test-secret"));
        store
            .revoke_attempt(BootstrapRole::Workload, GENERATION, "sandbox-env", ATTEMPT)
            .unwrap();
        assert!(!store.resource(opaque).exists());
        drop(store);
        let store = BootstrapStore::open_with_policies(
            tmp.path().join("repo"),
            tmp.path().join("state/signer.pk8"),
            tmp.path().join("renderer.py"),
            tmp.path().join("policy.rego"),
            tmp.path().join("as.rego"),
        )
        .unwrap();
        assert_eq!(
            store
                .load_workload_environment("sandbox-env", "ns", "uid")
                .unwrap(),
            environment
        );
        let new = store
            .publish_file(
                BootstrapRole::Workload,
                RESTART_GENERATION,
                "sandbox-env",
                "uid",
                &"1".repeat(64),
                "boundary.json",
                &bytes,
                &"b".repeat(96),
            )
            .unwrap();
        assert_ne!(new.sealed_descriptor, old.sealed_descriptor);
        assert!(
            store
                .load_workload_environment("another-sandbox", "ns", "uid")
                .is_err()
        );
        assert!(
            store
                .load_workload_environment("sandbox-env", "other-ns", "uid")
                .is_err()
        );
        assert!(
            store
                .load_workload_environment("sandbox-env", "ns", "another-uid")
                .is_err()
        );
        let mut changed = environment;
        changed.insert("TOKEN".into(), "replaced".into());
        assert!(matches!(
            store.record_workload_environment("sandbox-env", "ns", "uid", &changed),
            Err(StoreError::Conflict)
        ));
    }

    #[test]
    fn environment_delete_is_uid_scoped_and_invalid_private_state_fails_closed() {
        let (_tmp, store) = fixture();
        let env = std::collections::HashMap::from([("TOKEN".into(), "secret".into())]);
        store
            .record_workload_environment("sandbox-env", "ns", "old-uid", &env)
            .unwrap();
        store
            .record_workload_environment("sandbox-env", "ns", "new-uid", &env)
            .unwrap();
        let marker = store
            .begin_delete("sandbox-env", "ns", "old-uid", None)
            .unwrap();
        assert!(matches!(
            store.load_workload_environment("sandbox-env", "ns", "old-uid"),
            Err(StoreError::Revoked)
        ));
        store.revoke_pending_delete(&marker).unwrap();
        store.finish_delete(&marker).unwrap();
        store.finish_delete(&marker).unwrap();
        assert!(!store.workload_environment("ns", "old-uid").exists());
        assert_eq!(
            store
                .load_workload_environment("sandbox-env", "ns", "new-uid")
                .unwrap(),
            env
        );
        let path = store.workload_environment("ns", "new-uid");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(
            store
                .load_workload_environment("sandbox-env", "ns", "new-uid")
                .is_err()
        );
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        let mut record: WorkloadEnvironment =
            serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        record.sandbox_cr_uid = "old-uid".into();
        fs::write(&path, serde_json::to_vec(&record).unwrap()).unwrap();
        assert!(matches!(
            store.load_workload_environment("sandbox-env", "ns", "new-uid"),
            Err(StoreError::Conflict)
        ));
        fs::remove_file(&path).unwrap();
        assert!(
            store
                .load_workload_environment("sandbox-env", "ns", "new-uid")
                .is_err()
        );
    }

    #[test]
    #[ignore = "requires released Trustee processes; run tests/acceptance/check-trustee-api.py"]
    fn released_trustee_api_driver_publication() {
        let root =
            PathBuf::from(std::env::var("OPENSHELL_TEST_API_STATE").expect("isolated state"));
        let config = PathBuf::from(
            std::env::var("OPENSHELL_TEST_TRUSTEE_CONFIG").expect("isolated API config"),
        );
        let renderer = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../deployment/trustee/render-kbs-policy.py");
        let store = BootstrapStore::open_with_trustee(
            root.join("resources"),
            root.join("signer.pk8"),
            renderer,
            root.join("policy.rego"),
            root.join("as.rego"),
            &config,
        )
        .unwrap();
        if std::env::var("OPENSHELL_TEST_API_ACTION").as_deref() == Ok("revoke") {
            store.revoke_owned_sandbox("api-sandbox", None).unwrap();
            assert!(store.pending_revocations().unwrap().is_empty());
        } else {
            store
                .record_attempt("api-sandbox", "ns", "uid", GENERATION, ATTEMPT)
                .unwrap();
            let published = store
                .publish_file(
                    BootstrapRole::Workload,
                    GENERATION,
                    "api-sandbox",
                    "uid",
                    ATTEMPT,
                    "tls.key",
                    b"driver-api-integration-fixture",
                    INITDATA,
                )
                .unwrap();
            fs::write(
                root.join("receipt.json"),
                serde_json::to_vec(&serde_json::json!({"resource_path": published.resource_path}))
                    .unwrap(),
            )
            .unwrap();
        }
    }

    #[test]
    fn report_binding_snapshot_rejects_other_uid_attempt_and_revocation() {
        let (_temp, store) = fixture();
        store
            .record_attempt("reports", "ns", "uid", GENERATION, ATTEMPT)
            .unwrap();
        store
            .publish_file(
                BootstrapRole::Workload,
                GENERATION,
                "reports",
                "uid",
                ATTEMPT,
                "tls.key",
                b"test",
                INITDATA,
            )
            .unwrap();
        assert_eq!(
            store
                .attestation_bindings("reports", "ns", "uid")
                .unwrap()
                .len(),
            1
        );
        assert!(
            store
                .attestation_bindings("reports", "ns", "replacement-uid")
                .unwrap()
                .is_empty()
        );
        assert!(
            store
                .attestation_bindings("other", "ns", "uid")
                .unwrap()
                .is_empty()
        );
        let path = store
            .state
            .join("active-attempts")
            .join(format!("{}.json", workspace_hash("ns", "uid")));
        let original = read_private(&path).unwrap();
        let mut active: ActiveAttempt = serde_json::from_slice(&original).unwrap();
        active.attempt = "c".repeat(64);
        atomic_replace(&path, &serde_json::to_vec(&active).unwrap()).unwrap();
        assert!(
            store
                .attestation_bindings("reports", "ns", "uid")
                .unwrap()
                .is_empty()
        );
        atomic_replace(&path, &original).unwrap();
        store
            .revoke_attempt(BootstrapRole::Workload, GENERATION, "reports", ATTEMPT)
            .unwrap();
        assert!(
            store
                .attestation_bindings("reports", "ns", "uid")
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn trusted_launch_survives_reopen_and_rejects_replacement() {
        let (tmp, store) = fixture();
        let launch = crate::launch::LaunchIntent {
            sandbox_id: "sandbox-launch".into(), namespace: "ns".into(), sandbox_cr_uid: "uid".into(),
            sandbox_name: "native".into(), main_process_spec: "trusted command".into(), log_level: "info".into(),
            agent_uid: 1000, agent_gid: 1000, volume_claim_templates: serde_json::Value::Null,
            workload: serde_json::from_value(serde_json::json!({"apiVersion":"v1", "kind":"Pod",
                "spec":{"containers":[{"name":"agent", "image":"approved", "command":["native"]}],
                    "initContainers":[{"name":"openshell-sandbox-bootstrap", "image":"runtime-old"}, {"name":"workspace-init", "image":"approved"}],
                    "volumes":[{"name":"openshell-sandbox-bootstrap", "secret":{"secretName":"old"}}]}})).unwrap(),
        };
        store.record_launch(&launch).unwrap();
        let mut altered = launch.clone();
        altered.main_process_spec = "untrusted command".into();
        assert!(matches!(
            store.record_launch(&altered),
            Err(StoreError::Conflict)
        ));
        drop(store);
        let store = BootstrapStore::open_with_policies(
            tmp.path().join("repo"),
            tmp.path().join("state/signer.pk8"),
            tmp.path().join("renderer.py"),
            tmp.path().join("policy.rego"),
            tmp.path().join("as.rego"),
        )
        .unwrap();
        let restored = store.load_launch("sandbox-launch", "ns", "uid").unwrap();
        assert!(restored == launch);
        let config = crate::config::KubernetesComputeConfig {
            sandbox_runtime_image: "runtime-new".into(),
            ..Default::default()
        };
        let pod = restored
            .workload_for_generation("new", &["pull-new".into()], &config)
            .unwrap();
        let spec = pod.spec.unwrap();
        assert_eq!(spec.containers[0].command, Some(vec!["native".into()]));
        assert_eq!(spec.containers[0].image.as_deref(), Some("approved"));
        let init = spec.init_containers.unwrap();
        assert_eq!(init[0].image.as_deref(), Some("runtime-new"));
        assert_eq!(
            init[0].command,
            Some(vec!["/openshell-sandbox".into(), "bootstrap".into()])
        );
        assert_eq!(init[1].name, "workspace-init");
        assert_eq!(init[1].image.as_deref(), Some("approved"));
        assert_eq!(
            spec.volumes.unwrap()[0]
                .secret
                .as_ref()
                .unwrap()
                .secret_name
                .as_deref(),
            Some("new")
        );
        assert_eq!(spec.image_pull_secrets.unwrap()[0].name, "pull-new");
        assert!(store.load_launch("different-sandbox", "ns", "uid").is_err());
    }

    #[test]
    fn stopping_before_publication_tombstones_the_trusted_attempt() {
        let (_tmp, store) = fixture();
        store
            .record_attempt("sandbox-pending", "ns", "uid", GENERATION, ATTEMPT)
            .unwrap();
        store.revoke_owned_sandbox("sandbox-pending", None).unwrap();
        for role in [BootstrapRole::Workload, BootstrapRole::Supervisor] {
            assert!(matches!(
                store.publish_file(
                    role,
                    GENERATION,
                    "sandbox-pending",
                    "uid",
                    ATTEMPT,
                    "tls.key",
                    b"must-not-be-published",
                    INITDATA
                ),
                Err(StoreError::Revoked)
            ));
        }
        let next = "1".repeat(64);
        store
            .record_attempt("sandbox-pending", "ns", "uid", RESTART_GENERATION, &next)
            .unwrap();
        store
            .publish_file(
                BootstrapRole::Workload,
                RESTART_GENERATION,
                "sandbox-pending",
                "uid",
                &next,
                "tls.key",
                b"new-attempt",
                INITDATA,
            )
            .unwrap();
        store
            .revoke_owned_sandbox("sandbox-pending", Some("unrelated-uid"))
            .unwrap();
        assert!(
            store
                .publish_file(
                    BootstrapRole::Workload,
                    RESTART_GENERATION,
                    "sandbox-pending",
                    "uid",
                    &next,
                    "tls.key",
                    b"new-attempt",
                    INITDATA
                )
                .is_ok()
        );
    }

    #[test]
    fn measured_workspace_disk_ids_require_complete_same_uid_journals() {
        let (_tmp, store) = fixture();
        assert!(store.workspace_disk_ids("ns", "uid").unwrap().is_empty());
        store
            .record_workspace_volume("ns", "uid", "first", None, None)
            .unwrap();
        assert!(store.workspace_disk_ids("ns", "uid").unwrap().is_empty());
        store
            .record_workspace_volume("ns", "uid", "first", Some("pv-a"), Some("d-z"))
            .unwrap();
        store
            .record_workspace_volume("ns", "uid", "second", Some("pv-b"), Some("disk-a"))
            .unwrap();
        assert_eq!(
            store.workspace_disk_ids("ns", "uid").unwrap(),
            ["d-z", "disk-a"]
        );
        assert!(
            store
                .workspace_disk_ids("ns", "replacement-uid")
                .unwrap()
                .is_empty()
        );
        assert!(
            store
                .record_workspace_volume(
                    "ns",
                    "replacement-uid",
                    "first",
                    Some("pv-a"),
                    Some("d-z")
                )
                .is_err()
        );
        let path = store.workspace_journal(&workspace_hash("ns", "uid"));
        let mut journal: WorkspaceVolumeJournal =
            serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        journal.sandbox_cr_uid = "replacement-uid".to_string();
        atomic_replace(&path, &serde_json::to_vec(&journal).unwrap()).unwrap();
        assert!(matches!(
            store.workspace_disk_ids("ns", "uid"),
            Err(StoreError::Conflict)
        ));
    }

    #[test]
    fn pending_delete_survives_renderer_failure_and_reopen_without_erasing_workspace_key() {
        let (tmp, store) = fixture();
        let old = store
            .publish_file(
                BootstrapRole::Workload,
                GENERATION,
                "sandbox-delete",
                "old-uid",
                ATTEMPT,
                "bootstrap.toml",
                b"old-secret",
                INITDATA,
            )
            .unwrap();
        let supervisor = store
            .publish_file(
                BootstrapRole::Supervisor,
                GENERATION,
                "sandbox-delete",
                "old-uid",
                ATTEMPT,
                "supervisor.toml",
                b"supervisor-secret",
                INITDATA,
            )
            .unwrap();
        let replacement_attempt = "b".repeat(64);
        let replacement_bootstrap = store
            .publish_file(
                BootstrapRole::Workload,
                GENERATION,
                "sandbox-delete",
                "replacement-uid",
                &replacement_attempt,
                "replacement.toml",
                b"replacement-secret",
                &"b".repeat(96),
            )
            .unwrap();
        let replacement_bootstrap_serving = store.repository.join(staged_resource_key(
            replacement_bootstrap
                .resource_path
                .strip_prefix("resource/")
                .unwrap(),
        ));
        store
            .record_workspace_owner("sandbox-delete", "namespace", "old-uid")
            .unwrap();
        store
            .record_workspace_volume("namespace", "old-uid", "old-pvc", None, None)
            .unwrap();
        let workspace = store
            .ensure_workspace_key("namespace", "old-uid", INITDATA)
            .unwrap();
        let old_workspace_serving = store.repository.join(staged_resource_key(
            workspace.resource_path.strip_prefix("resource/").unwrap(),
        ));
        let private_key = store.workspace_key(&workspace_hash("namespace", "old-uid"));
        let key = read_private(&private_key).unwrap();

        let marker = store
            .begin_delete(
                "sandbox-delete",
                "namespace",
                "old-uid",
                Some((GENERATION, ATTEMPT)),
            )
            .unwrap();
        store
            .record_workspace_owner("sandbox-delete", "namespace", "replacement-uid")
            .unwrap();
        store
            .record_workspace_volume(
                "namespace",
                "replacement-uid",
                "replacement-pvc",
                None,
                None,
            )
            .unwrap();
        let replacement = store
            .ensure_workspace_key("namespace", "replacement-uid", &"b".repeat(96))
            .unwrap();
        let replacement_serving = store.repository.join(staged_resource_key(
            replacement.resource_path.strip_prefix("resource/").unwrap(),
        ));
        assert!(matches!(
            store.publish_file(
                BootstrapRole::Workload,
                GENERATION,
                "sandbox-delete",
                "old-uid",
                ATTEMPT,
                "another.toml",
                b"late",
                INITDATA,
            ),
            Err(StoreError::Revoked)
        ));
        assert!(matches!(
            store.ensure_workspace_key("namespace", "old-uid", INITDATA),
            Err(StoreError::Revoked)
        ));
        fs::write(tmp.path().join("fail"), b"1").unwrap();
        assert!(matches!(
            store.revoke_pending_delete(&marker),
            Err(StoreError::Cleanup(_))
        ));
        assert!(!old_workspace_serving.exists());
        assert!(replacement_serving.exists());
        assert!(replacement_bootstrap_serving.exists());
        assert!(
            !store
                .repository
                .join(staged_resource_key(
                    old.resource_path.strip_prefix("resource/").unwrap()
                ))
                .exists()
        );
        assert!(
            !store
                .repository
                .join(staged_resource_key(
                    supervisor.resource_path.strip_prefix("resource/").unwrap()
                ))
                .exists()
        );
        assert_eq!(store.pending_deletes().unwrap(), vec![marker.clone()]);
        fs::remove_file(tmp.path().join("fail")).unwrap();
        drop(store);

        let reopened = BootstrapStore::open_with_policies(
            tmp.path().join("repo"),
            tmp.path().join("state/signer.pk8"),
            tmp.path().join("renderer.py"),
            tmp.path().join("policy.rego"),
            tmp.path().join("as.rego"),
        )
        .unwrap();
        reopened.revoke_pending_delete(&marker).unwrap();
        assert!(
            !reopened
                .repository
                .join(staged_resource_key(
                    old.resource_path.strip_prefix("resource/").unwrap()
                ))
                .exists()
        );
        assert_eq!(read_private(&private_key).unwrap(), key);
        assert!(
            replacement_serving.exists(),
            "old UID cleanup must preserve replacement key"
        );
        assert!(
            replacement_bootstrap_serving.exists(),
            "old UID cleanup must preserve replacement bootstrap"
        );
        reopened.finish_delete(&marker).unwrap();
        assert!(reopened.pending_deletes().unwrap().is_empty());
        assert_eq!(reopened.workspace_owners().unwrap().len(), 1);
        assert!(private_key.exists());
    }

    #[test]
    fn opening_production_store_replays_pending_delete_before_returning() {
        let (tmp, store) = fixture();
        let published = store
            .publish_file(
                BootstrapRole::Workload,
                GENERATION,
                "sandbox-crash",
                "cr-uid",
                ATTEMPT,
                "secret",
                b"private",
                INITDATA,
            )
            .unwrap();
        let resource = store.repository.join(staged_resource_key(
            published.resource_path.strip_prefix("resource/").unwrap(),
        ));
        let marker = store
            .begin_delete(
                "sandbox-crash",
                "namespace",
                "cr-uid",
                Some((GENERATION, ATTEMPT)),
            )
            .unwrap();
        assert!(resource.exists());
        let interrupted_write = tmp.path().join("state/pending-deletes/.tmp-interrupted");
        fs::write(&interrupted_write, b"partial marker").unwrap();
        drop(store);
        let reopened = BootstrapStore::open_with_policies(
            tmp.path().join("repo"),
            tmp.path().join("state/signer.pk8"),
            tmp.path().join("renderer.py"),
            tmp.path().join("policy.rego"),
            tmp.path().join("as.rego"),
        )
        .unwrap();
        assert!(!resource.exists());
        assert!(!interrupted_write.exists());
        assert_eq!(reopened.pending_deletes().unwrap(), vec![marker]);
    }

    #[test]
    fn uid_scoped_revoke_withdraws_every_old_file_even_if_policy_render_fails() {
        let (tmp, store) = fixture();
        let old_a = store
            .publish_file(
                BootstrapRole::Workload,
                GENERATION,
                "sandbox-stop",
                "old-uid",
                ATTEMPT,
                "old-a",
                b"a",
                INITDATA,
            )
            .unwrap();
        let old_b = store
            .publish_file(
                BootstrapRole::Supervisor,
                GENERATION,
                "sandbox-stop",
                "old-uid",
                ATTEMPT,
                "old-b",
                b"b",
                INITDATA,
            )
            .unwrap();
        let replacement = store
            .publish_file(
                BootstrapRole::Workload,
                GENERATION,
                "sandbox-stop",
                "new-uid",
                &"b".repeat(64),
                "new",
                b"new",
                &"b".repeat(96),
            )
            .unwrap();
        let calls_before: usize = fs::read_to_string(tmp.path().join("renderer-calls"))
            .unwrap()
            .parse()
            .unwrap();
        fs::write(tmp.path().join("fail"), b"fail").unwrap();
        assert!(matches!(
            store.revoke_sandbox_uid("sandbox-stop", "old-uid"),
            Err(StoreError::Cleanup(_))
        ));
        for old in [old_a, old_b] {
            assert!(
                !store
                    .repository
                    .join(staged_resource_key(
                        old.resource_path.strip_prefix("resource/").unwrap()
                    ))
                    .exists()
            );
        }
        assert!(
            store
                .repository
                .join(staged_resource_key(
                    replacement.resource_path.strip_prefix("resource/").unwrap()
                ))
                .exists()
        );
        fs::remove_file(tmp.path().join("fail")).unwrap();
        store.revoke_sandbox_uid("sandbox-stop", "old-uid").unwrap();
        store.revoke_sandbox_uid("sandbox-stop", "old-uid").unwrap();
        let calls_after: usize = fs::read_to_string(tmp.path().join("renderer-calls"))
            .unwrap()
            .parse()
            .unwrap();
        assert_eq!(
            calls_after,
            calls_before + 2,
            "one publication per batch plus the failed attempt"
        );
    }

    #[test]
    fn signed_descriptor_is_native_vault_and_does_not_contain_plaintext() {
        let (_tmp, store) = fixture();
        let raw = b"private-bootstrap-file\0with binary data";
        let planned = store
            .plan_file(
                BootstrapRole::Workload,
                GENERATION,
                "sandbox-1",
                ATTEMPT,
                "auth.json",
            )
            .unwrap();
        assert!(
            store
                .plan_file(
                    BootstrapRole::Workload,
                    RESTART_GENERATION,
                    "sandbox-1",
                    ATTEMPT,
                    "auth.json"
                )
                .is_ok()
        );
        assert!(
            !store
                .resource(planned.resource_uri.rsplit('/').next().unwrap())
                .exists()
        );
        let secret = store
            .publish_file(
                BootstrapRole::Workload,
                GENERATION,
                "sandbox-1",
                "cr-uid",
                ATTEMPT,
                "auth.json",
                raw,
                INITDATA,
            )
            .unwrap();
        assert_eq!(planned.resource_uri, secret.resource_uri);
        assert_eq!(
            read_regular(&store.resource(secret.resource_uri.rsplit('/').next().unwrap())).unwrap(),
            raw
        );
        assert!(!secret.sealed_descriptor.contains("private-bootstrap-file"));
        assert!(
            !secret
                .sealed_descriptor
                .contains(&URL_SAFE_NO_PAD.encode(raw))
        );

        let parts: Vec<_> = secret.sealed_descriptor.split('.').collect();
        assert_eq!(parts.len(), 4);
        assert_eq!(parts[0], "sealed");
        let header: serde_json::Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[1]).unwrap()).unwrap();
        let payload: serde_json::Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[2]).unwrap()).unwrap();
        assert_eq!(header["alg"], "ES256");
        assert_eq!(header["kid"], SIGNER_URI);
        assert_eq!(payload["version"], "0.1.0");
        assert_eq!(payload["type"], "vault");
        assert_eq!(payload["name"], planned.resource_uri);
        assert_eq!(payload["provider"], "kbs");

        let jwk: serde_json::Value = serde_json::from_slice(
            &read_regular(
                &store
                    .repository
                    .join(staged_resource_key("default/bootstrap-signer/key")),
            )
            .unwrap(),
        )
        .unwrap();
        let mut point = vec![4];
        point.extend(URL_SAFE_NO_PAD.decode(jwk["x"].as_str().unwrap()).unwrap());
        point.extend(URL_SAFE_NO_PAD.decode(jwk["y"].as_str().unwrap()).unwrap());
        let verifier = UnparsedPublicKey::new(&ECDSA_P256_SHA256_FIXED, point);
        let input = format!("{}.{}", parts[1], parts[2]);
        let sig = URL_SAFE_NO_PAD.decode(parts[3]).unwrap();
        verifier.verify(input.as_bytes(), &sig).unwrap();
        let tampered = format!("{}.{}x", parts[1], parts[2]);
        assert!(verifier.verify(tampered.as_bytes(), &sig).is_err());
    }

    #[test]
    fn retry_conflict_renderer_failure_and_revocation_are_fail_closed() {
        let (tmp, store) = fixture();
        let role = BootstrapRole::Supervisor;
        let planned = store
            .plan_file(role, GENERATION, "sandbox-2", ATTEMPT, "config.toml")
            .unwrap();
        let id = planned.resource_uri.rsplit('/').next().unwrap();
        fs::write(tmp.path().join("fail"), b"1").unwrap();
        assert!(matches!(
            store.publish_file(
                role,
                GENERATION,
                "sandbox-2",
                "cr-uid",
                ATTEMPT,
                "config.toml",
                b"one",
                INITDATA
            ),
            Err(StoreError::Policy)
        ));
        assert!(!store.resource(id).exists());
        fs::remove_file(tmp.path().join("fail")).unwrap();
        fs::write(tmp.path().join("fail_after_as"), b"1").unwrap();
        assert!(matches!(
            store.publish_file(
                role,
                GENERATION,
                "sandbox-2",
                "cr-uid",
                ATTEMPT,
                "config.toml",
                b"one",
                INITDATA
            ),
            Err(StoreError::Policy)
        ));
        assert!(!store.resource(id).exists());
        assert!(
            !fs::read_to_string(tmp.path().join("as.rego"))
                .unwrap()
                .contains(INITDATA)
        );
        fs::remove_file(tmp.path().join("fail_after_as")).unwrap();
        let first = store
            .publish_file(
                role,
                GENERATION,
                "sandbox-2",
                "cr-uid",
                ATTEMPT,
                "config.toml",
                b"one",
                INITDATA,
            )
            .unwrap();
        let retry = store
            .publish_file(
                role,
                GENERATION,
                "sandbox-2",
                "cr-uid",
                ATTEMPT,
                "config.toml",
                b"one",
                INITDATA,
            )
            .unwrap();
        assert_eq!(first.resource_uri, retry.resource_uri);
        assert_eq!(first.sealed_descriptor, retry.sealed_descriptor);
        assert!(matches!(
            store.publish_file(
                role,
                GENERATION,
                "sandbox-2",
                "cr-uid",
                ATTEMPT,
                "config.toml",
                b"two",
                INITDATA
            ),
            Err(StoreError::Conflict)
        ));
        assert!(matches!(
            store.publish_file(
                role,
                GENERATION,
                "sandbox-2",
                "cr-uid",
                ATTEMPT,
                "config.toml",
                b"one",
                &"b".repeat(96)
            ),
            Err(StoreError::Conflict)
        ));
        fs::write(tmp.path().join("fail"), b"1").unwrap();
        assert!(matches!(
            store.revoke_attempt(role, GENERATION, "sandbox-2", ATTEMPT),
            Err(StoreError::Cleanup(_))
        ));
        assert!(!store.resource(id).exists());
        let identity = identity_hash(role, GENERATION, "sandbox-2", ATTEMPT);
        assert!(store.revoking(&identity).exists());
        assert!(matches!(
            store.publish_file(
                role,
                GENERATION,
                "sandbox-2",
                "cr-uid",
                ATTEMPT,
                "config.toml",
                b"one",
                INITDATA
            ),
            Err(StoreError::Revoked)
        ));
        fs::remove_file(tmp.path().join("fail")).unwrap();
        store.revoke_sandbox_uid("sandbox-2", "cr-uid").unwrap();
        store.revoke_sandbox_uid("sandbox-2", "cr-uid").unwrap();
        assert!(!store.resource(id).exists());
        assert!(!store.revoking(&identity).exists());
        assert!(matches!(
            store.publish_file(
                role,
                GENERATION,
                "sandbox-2",
                "cr-uid",
                ATTEMPT,
                "config.toml",
                b"one",
                INITDATA
            ),
            Err(StoreError::Revoked)
        ));
    }

    #[test]
    fn deleted_sandbox_name_can_be_recreated_with_a_new_volume() {
        let (_tmp, store) = fixture();
        let namespace = "openshell";
        let pvc = "workspace-default--opencode-demo";
        store
            .record_workspace_owner("sandbox-old", namespace, "old-cr-uid")
            .unwrap();
        store
            .record_workspace_volume(
                namespace,
                "old-cr-uid",
                pvc,
                Some("old-pv-uid"),
                Some("d-old"),
            )
            .unwrap();
        store
            .ensure_workspace_key(namespace, "old-cr-uid", INITDATA)
            .unwrap();
        let old_id = workspace_hash(namespace, "old-cr-uid");
        let old_key = read_private(&store.workspace_key(&old_id)).unwrap();
        let marker = store
            .begin_delete("sandbox-old", namespace, "old-cr-uid", None)
            .unwrap();
        store.revoke_pending_delete(&marker).unwrap();
        store.finish_delete(&marker).unwrap();
        assert!(!store.workspace_resource(&old_id).exists());
        assert!(store.workspace_journal(&old_id).exists());

        store
            .record_workspace_owner("sandbox-new", namespace, "new-cr-uid")
            .unwrap();
        store
            .record_workspace_volume(namespace, "new-cr-uid", pvc, None, None)
            .unwrap();
        store
            .record_workspace_volume(
                namespace,
                "new-cr-uid",
                pvc,
                Some("new-pv-uid"),
                Some("d-new"),
            )
            .unwrap();
        store
            .ensure_workspace_key(namespace, "new-cr-uid", INITDATA)
            .unwrap();
        assert_ne!(
            old_key,
            read_private(&store.workspace_key(&workspace_hash(namespace, "new-cr-uid"))).unwrap()
        );

        // A reusable name must not permit reusing an old physical volume or
        // replacing the volume already bound to the current CR identity.
        for (uid, pv, disk) in [
            ("pv-rebind-uid", "old-pv-uid", "d-unrelated"),
            ("disk-rebind-uid", "unrelated-pv-uid", "d-old"),
            ("new-cr-uid", "changed-pv-uid", "d-changed"),
        ] {
            assert!(matches!(
                store.record_workspace_volume(namespace, uid, pvc, Some(pv), Some(disk)),
                Err(StoreError::Conflict)
            ));
        }
    }

    #[test]
    fn workspace_key_is_stable_and_access_can_rotate() {
        let (tmp, store) = fixture();
        let planned = store.plan_workspace_key("workspace", "cr-uid-1").unwrap();
        assert_eq!(planned.resource_uri.split('/').count(), 6);
        store
            .record_workspace_owner("sandbox-workspace", "workspace", "cr-uid-1")
            .unwrap();
        store
            .record_workspace_volume("workspace", "cr-uid-1", "pvc-a", None, None)
            .unwrap();
        store
            .record_workspace_volume(
                "workspace",
                "cr-uid-1",
                "pvc-a",
                Some("pv-a"),
                Some("disk-a"),
            )
            .unwrap();
        store
            .record_workspace_volume("workspace", "different-cr", "pvc-a", None, None)
            .unwrap();
        assert!(matches!(
            store.record_workspace_volume(
                "workspace",
                "different-cr",
                "pvc-a",
                Some("pv-a"),
                Some("disk-a")
            ),
            Err(StoreError::Conflict)
        ));
        assert!(matches!(
            store.record_workspace_volume(
                "other-workspace",
                "different-cr",
                "pvc-z",
                Some("pv-a"),
                None
            ),
            Err(StoreError::Conflict)
        ));
        let first = store
            .ensure_workspace_key("workspace", "cr-uid-1", INITDATA)
            .unwrap();
        assert_eq!(first.resource_uri, planned.resource_uri);
        let id = planned.resource_uri.rsplit('/').next().unwrap();
        let private = store.workspace_key(id);
        let original = read_regular(&private).unwrap();
        assert_eq!(original.len(), 32);
        assert_eq!(
            read_regular(&store.workspace_resource(id)).unwrap(),
            original
        );
        let new_digest = "b".repeat(96);
        fs::write(tmp.path().join("fail"), b"1").unwrap();
        assert!(matches!(
            store.ensure_workspace_key("workspace", "cr-uid-1", &new_digest),
            Err(StoreError::Policy)
        ));
        assert!(!store.workspace_resource(id).exists());
        assert_eq!(read_regular(&private).unwrap(), original);
        fs::remove_file(tmp.path().join("fail")).unwrap();
        store
            .ensure_workspace_key("workspace", "cr-uid-1", &new_digest)
            .unwrap();
        store
            .deauthorize_workspace_key("workspace", "cr-uid-1")
            .unwrap();
        assert!(!store.workspace_resource(id).exists());
        assert_eq!(read_regular(&private).unwrap(), original);
        store
            .ensure_workspace_key("workspace", "cr-uid-1", &new_digest)
            .unwrap();
        assert_eq!(
            read_regular(&store.workspace_resource(id)).unwrap(),
            original
        );
        let binding: WorkspaceBinding =
            serde_json::from_slice(&read_regular(&store.workspace_binding(id)).unwrap()).unwrap();
        assert_eq!(binding.initdata_sha384, new_digest);
        store
            .deauthorize_workspace_key("workspace", "cr-uid-1")
            .unwrap();
    }

    #[test]
    fn workspace_owner_index_recovers_deauthorization_after_cr_deletion() {
        let (tmp, store) = fixture();
        assert!(matches!(
            store.ensure_workspace_key("workspace", "deleted-cr-uid", INITDATA),
            Err(StoreError::Invalid("workspace owner not recorded"))
        ));
        store
            .record_workspace_owner("sandbox-reopen", "workspace", "deleted-cr-uid")
            .unwrap();
        store
            .record_workspace_volume("workspace", "deleted-cr-uid", "retained-pvc", None, None)
            .unwrap();
        let planned = store
            .ensure_workspace_key("workspace", "deleted-cr-uid", INITDATA)
            .unwrap();
        let id = planned.resource_uri.rsplit('/').next().unwrap().to_owned();
        assert!(store.workspace_resource(&id).exists());
        drop(store);

        let reopened = BootstrapStore::open_with_policies(
            tmp.path().join("repo"),
            tmp.path().join("state/signer.pk8"),
            tmp.path().join("renderer.py"),
            tmp.path().join("policy.rego"),
            tmp.path().join("as.rego"),
        )
        .unwrap();
        let owners = reopened.workspace_owners().unwrap();
        assert_eq!(owners.len(), 1);
        let owner = &owners[0];
        let marker = reopened
            .begin_delete(
                &owner.sandbox_id,
                &owner.namespace,
                &owner.sandbox_cr_uid,
                None,
            )
            .unwrap();
        fs::write(tmp.path().join("fail"), b"1").unwrap();
        assert!(matches!(
            reopened.revoke_pending_delete(&marker),
            Err(StoreError::Cleanup(_))
        ));
        assert!(!reopened.workspace_resource(&id).exists());
        fs::remove_file(tmp.path().join("fail")).unwrap();
        reopened.revoke_pending_delete(&marker).unwrap();
        reopened.revoke_pending_delete(&marker).unwrap();
        reopened.finish_delete(&marker).unwrap();
        assert!(reopened.workspace_owners().unwrap().is_empty());
        assert!(reopened.pending_deletes().unwrap().is_empty());
        assert!(!reopened.workspace_resource(&id).exists());
        assert!(!reopened.workspace_binding(&id).exists());
        assert!(reopened.workspace_key(&id).exists());
        assert!(
            !fs::read_to_string(tmp.path().join("as.rego"))
                .unwrap()
                .contains(INITDATA)
        );
    }

    #[test]
    fn production_renderer_accepts_store_bindings_and_rejects_mutation() {
        let renderer = std::env::var_os("KBS_POLICY_RENDERER").map_or_else(
            || {
                Path::new(env!("CARGO_MANIFEST_DIR"))
                    .join("../../deployment/trustee/render-kbs-policy.py")
            },
            PathBuf::from,
        );
        assert!(
            renderer.is_file(),
            "production KBS policy renderer is missing: {}",
            renderer.display()
        );
        let tmp = tempfile::tempdir().unwrap();
        let policy = tmp.path().join("policy.rego");
        let as_policy = tmp.path().join("as.rego");
        let store = BootstrapStore::open_with_policies(
            tmp.path().join("repo"),
            tmp.path().join("state/signer.pk8"),
            renderer,
            &policy,
            &as_policy,
        )
        .unwrap();
        let published = store
            .publish_file(
                BootstrapRole::Workload,
                RESTART_GENERATION,
                "sandbox-policy",
                "cr-uid",
                ATTEMPT,
                "token",
                b"raw",
                INITDATA,
            )
            .unwrap();
        store
            .record_workspace_volume("workspace", "cr-uid-2", "pvc-b", None, None)
            .unwrap();
        store
            .record_workspace_owner("sandbox-policy", "workspace", "cr-uid-2")
            .unwrap();
        store
            .ensure_workspace_key("workspace", "cr-uid-2", INITDATA)
            .unwrap();
        let policy_text = fs::read_to_string(&policy).unwrap();
        assert!(policy_text.contains(&published.resource_path));
        assert!(policy_text.contains("resource/default/workspace/"));
        assert!(fs::read_to_string(&as_policy).unwrap().contains(INITDATA));
        let original_binding = read_regular(&published.binding_path).unwrap();
        let mut binding: serde_json::Value = serde_json::from_slice(&original_binding).unwrap();
        binding["generation"] = "0".repeat(64).into();
        atomic_replace(
            &published.binding_path,
            &serde_json::to_vec(&binding).unwrap(),
        )
        .unwrap();
        assert!(matches!(store.refresh_policy(), Err(StoreError::Policy)));
        atomic_replace(&published.binding_path, &original_binding).unwrap();
        store
            .revoke_attempt(
                BootstrapRole::Workload,
                RESTART_GENERATION,
                "sandbox-policy",
                ATTEMPT,
            )
            .unwrap();
        assert!(fs::read_to_string(&as_policy).unwrap().contains(INITDATA));
        store
            .deauthorize_workspace_key("workspace", "cr-uid-2")
            .unwrap();
        assert!(!fs::read_to_string(&as_policy).unwrap().contains(INITDATA));
    }
}
