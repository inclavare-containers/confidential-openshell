# Upstream provenance and local changes

This crate derives from NVIDIA OpenShell's Apache-2.0 `openshell-driver-kubernetes` at v0.1.6,
commit `ac7f615cd12d5cc49cb16eb1f5f10ffeb1e90f47`. The original
[crate README](../../repos/openshell/crates/openshell-driver-kubernetes/README.md) and
[NVIDIA copyright and Apache-2.0 license](../../repos/openshell/LICENSE) are retained in the
pinned submodule. Derived Rust files retain their copyright and SPDX headers. The repository
uses the pinned source directly.

[UPSTREAM-SOURCES.json](UPSTREAM-SOURCES.json) records SHA-256 for every upstream Rust source,
crate manifest and README. It identifies directly imported modules and the
`sandbox_runtime`/`isolation` implementations delegated through local wrappers. Tests in those
imported implementations compile with this crate. `lifecycle_tests.rs` is ported with the
confidential fixture field added and is included in the driver test module. `driver.rs` and `main.rs` remain local
derivations; `confidential.rs` and the private `bootstrap.rs` resource publisher are
project-owned code. Their responsibilities and retained state are described in the
[component README](README.md).

From the repository root, run `components/confidential-driver/check-upstream-provenance.sh` to verify
the pinned commit, source hashes and import paths. It prints a diff statistic for derived
files; it does not approve or constrain their changes. Package naming and dependency
paths differ because this driver builds in the integration workspace. The submodule stays
unchanged; the source manifest records provenance; tests and code review validate the local changes.

The CoCo 0.22 integration keeps official AA/CDH and Trustee binaries unchanged. Its local
publisher uses Trustee's authenticated management APIs, while measured role/attempt
authorization, workspace ownership and recovery journals remain project-owned contracts.
Native OpenShell authentication and protocol remain upstream.
