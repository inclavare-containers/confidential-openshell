# Upstream provenance and controlled delta

This crate derives from NVIDIA OpenShell's Apache-2.0 `openshell-driver-kubernetes` at v0.1.3,
commit `e1f3c82caa3ed3b65de22889ae7ef32a774878ef`. The original
[crate README](../../repos/openshell/crates/openshell-driver-kubernetes/README.md) and
[NVIDIA copyright and Apache-2.0 license](../../repos/openshell/LICENSE) are retained in the
pinned submodule. Derived Rust files retain their copyright and SPDX headers. The repository
uses the pinned source directly.

[UPSTREAM-SOURCES.json](UPSTREAM-SOURCES.json) records SHA-256 for every upstream Rust source,
crate manifest and README. It identifies five directly imported modules and the
`sandbox_runtime`/`isolation` implementations delegated through local wrappers. Tests in those
imported implementations compile with this crate. `driver.rs` and `main.rs` remain local
derivations; `confidential.rs` and the private `bootstrap.rs` resource publisher are
project-owned code. Their responsibilities and retained state are described in the
[component README](README.md).

From the repository root, run `components/confidential-driver/controlled-diff.sh` to verify
the pinned commit, source hashes, import paths and local delta. Package naming and dependency
paths differ because this driver builds in the integration workspace. The submodule stays
unchanged; the source manifest and controlled diff identify the local derivation.

The CoCo 0.22 integration keeps official AA/CDH and Trustee binaries unchanged. Its local
publisher adapts Trustee's flat KV resource storage, while measured role/attempt
authorization, workspace ownership and recovery journals remain project-owned contracts.
Native OpenShell authentication and protocol remain upstream.
