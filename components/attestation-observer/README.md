# Passive attestation observer

Optional display-only companion for the unmodified Trustee images from the
post-v0.22.0 commit pinned in the [runtime lock](../../deployment/runtime/artifacts.lock.json).
It verifies existing session EAR signatures, persists a bounded-field summary
per initdata digest, and serves read-only queries through the official KBS
external-plugin protocol. It never initiates attestation or retrieves resources.

See [deployment and report semantics](../../docs/attestation-records.md).
`UPSTREAM-SOURCES.json` records the unchanged upstream plugin proto provenance.
The session-file adapter is version-bound and must be reviewed on Trustee upgrades.
