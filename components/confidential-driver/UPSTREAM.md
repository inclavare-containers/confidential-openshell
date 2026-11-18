# Upstream provenance and local changes

This crate derives from NVIDIA OpenShell's Apache-2.0 `openshell-driver-kubernetes` at v0.1.9,
commit `ce58cf8e9b953281352d98a637e41616295b1318`. The original
[crate README](../../repos/openshell/crates/openshell-driver-kubernetes/README.md) and
[NVIDIA copyright and Apache-2.0 license](../../repos/openshell/LICENSE) are retained in the
pinned submodule. Derived Rust files retain their copyright and SPDX headers. The repository
uses the pinned source directly.

[UPSTREAM-SOURCES.json](UPSTREAM-SOURCES.json) records SHA-256 for every upstream Rust source,
crate manifest and README. It identifies directly imported modules and the
`sandbox_runtime`/`isolation` implementations delegated through local wrappers. Tests in those
imported implementations compile with this crate. `lifecycle_tests.rs` is ported with the
confidential fixture field added and is included in the driver test module. `driver.rs`, `main.rs` and `image_update.rs` are local
derivations. Stopped configuration updates apply to the trusted launch record. `confidential.rs` and the private `bootstrap.rs` resource publisher are
project-owned code. Their responsibilities and retained state are described in the
[component README](README.md).

From the repository root, run `components/confidential-driver/check-upstream-provenance.sh` to verify
the pinned commit, source hashes and import paths. It prints a diff statistic for derived
files; it does not approve or constrain their changes. Package naming and dependency
paths differ because this driver builds in the integration workspace. The submodule stays
unchanged; the source manifest records provenance; tests and code review validate the local changes.

The integration uses unchanged official AA/CDH and Trustee binaries from guest-components v0.23.1 and Trustee v0.23.0. Exact source commits and artifact digests are recorded in the
[guest lock](../../deployment/artifacts.lock.json) and
[runtime lock](../../deployment/runtime/artifacts.lock.json). Its local
publisher uses Trustee's authenticated management APIs, while measured role/attempt
authorization, workspace ownership and recovery journals remain project-owned contracts.
Native OpenShell authentication and protocol remain upstream.
