#!/usr/bin/env bash
set -euo pipefail
export PATH="/usr/local/go/bin:$PATH"
umask 077
export LC_ALL=C

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
source_root="${root}/.local/build-sources/cloud-api-adaptor"
source_dir="${source_root}/src/cloud-api-adaptor"
test "$(git -C "${source_root}" write-tree)" = "$(jq -r '.["cloud-api-adaptor"].result_tree' "${root}/deployment/build/sources.lock.json")"
git -C "${source_root}" diff --quiet
artifacts="${root}/artifacts"
lock="${root}/deployment/artifacts.lock.json"
archive="${artifacts}/guest-payload.tar"
mkdir -p "${artifacts}/cache"
for command in jq curl sha256sum tar zstd make go find readelf crane runc; do
    command -v "${command}" >/dev/null || { echo "missing command: ${command}" >&2; exit 1; }
done
jq -e '.schema == 1 and .platform == "linux/amd64"' "${lock}" >/dev/null

# Record the exact local CAA adapter sources, guest overlay, and packaging
# recipe. A submodule revision alone does not describe in-progress local
# provider changes, and a mid-build edit must not silently enter the payload.
payload_inputs_sha256() {
    (
        cd "${root}"
        find .local/build-sources/cloud-api-adaptor/src/cloud-api-adaptor -type f \
            \( -name '*.go' -o -name 'go.mod' -o -name 'go.sum' -o -name 'Makefile' \
               -o -path '*/podvm/files/*' \) ! -path '*/__pycache__/*' ! -name '*.pyc' -print0
        find deployment/guest/files -type f ! -path '*/__pycache__/*' ! -name '*.pyc' -print0
        printf '%s\0' deployment/guest/{build-payload,build-cdh-tool}.sh deployment/artifacts.lock.json
    ) | sort -z | xargs -0 sha256sum | sha256sum | cut -d' ' -f1
}
input_sources_sha256="$(payload_inputs_sha256)"

work="$(mktemp -d "${artifacts}/.guest-payload.XXXXXX")"
trap 'rm -rf -- "${work}"' EXIT
tree="${work}/root"
mkdir -p "${tree}"
cp -a "${source_dir}/podvm/files/." "${tree}/"
# Copy the same overlay files included in the input digest, without local empty directories.
(
    cd "${root}/deployment/guest/files"
    find . -type f ! -path '*/__pycache__/*' ! -name '*.pyc' -print0 \
        | tar --null -T - -cf -
) | tar -xf - -C "${tree}"
find "${tree}" -type d -name __pycache__ -prune -exec rm -rf -- {} +
find "${tree}" -type f -name '*.pyc' -delete

# The APF/PUD adapters use the pinned patch tree. AA/CDH, Kata and pause
# are unmodified checksum-pinned upstream artifacts.
make -C "${source_dir}" RELEASE_BUILD=true BUILTIN_CLOUD_PROVIDERS=alibabacloud \
    agent-protocol-forwarder process-user-data
for binary in agent-protocol-forwarder process-user-data; do
    install -D -m 0755 "${source_dir}/${binary}" "${tree}/usr/local/bin/${binary}"
done

for binary in attestation-agent confidential-data-hub api-server-rest; do
    expected="$(jq -r --arg name "${binary}" '.guest_components.binaries[$name].binary_sha256' "${lock}")"
    cached="${artifacts}/cache/${binary}-$(jq -r '.guest_components.commit' "${lock}")"
    if ! [[ -f "${cached}" && ! -L "${cached}" ]] ||
        ! printf '%s  %s\n' "${expected}" "${cached}" | sha256sum -c - >/dev/null 2>&1; then
        command -v oras >/dev/null
        command -v gh >/dev/null
        reference="$(jq -r --arg name "${binary}" '.guest_components.binaries[$name].ref' "${lock}")"
        mkdir -p "${work}/${binary}"
        (
            cd "${work}/${binary}"
            "${source_dir}/hack/verify-provenance.sh" -s -a "${reference}" \
                -r "$(jq -r '.guest_components.repository' "${lock}")" \
                -d "$(jq -r '.guest_components.commit' "${lock}")"
            oras pull "${reference}"
            tar -xJf "$(jq -r --arg name "${binary}" '.guest_components.binaries[$name].archive' "${lock}")"
            printf '%s  %s\n' "${expected}" "${binary}" | sha256sum -c -
            install -m 0755 "${binary}" "${cached}"
        )
    fi
    printf '%s  %s\n' "${expected}" "${cached}" | sha256sum -c -
    install -D -m 0755 "${cached}" "${tree}/usr/local/bin/${binary}"
done

cdh_tool="ttrpc-cdh-tool"
cdh_cached="${artifacts}/cache/${cdh_tool}-$(jq -er '.guest_components.commit' "${lock}")"
expected_cdh_tool="$(jq -er '.guest_components.binaries["ttrpc-cdh-tool"].binary_sha256' "${lock}")"
if ! printf '%s  %s\n' "${expected_cdh_tool}" "${cdh_cached}" | sha256sum -c - >/dev/null 2>&1; then
    "${root}/deployment/guest/build-cdh-tool.sh" "${work}/cdh-tool"
    built_cdh_tool="${work}/cdh-tool/target/release/${cdh_tool}"
    printf '%s  %s\n' "${expected_cdh_tool}" "${built_cdh_tool}" | sha256sum -c -
    install -m 0755 "${built_cdh_tool}" "${cdh_cached}"
fi
install -D -m 0755 "${cdh_cached}" "${tree}/usr/local/bin/${cdh_tool}"

agent_version=$(jq -er .kata_agent.version "$lock")
agent="${KATA_AGENT_BIN:-${artifacts}/cache/kata-agent-${agent_version}}"
expected_agent="$(jq -r '.kata_agent.binary_sha256' "${lock}")"
if [[ ! -f "${agent}" ]]; then
    # Follow CAA: fetch the standalone, provenance-verified official OCI agent.
    command -v oras >/dev/null
    command -v gh >/dev/null
    reference="$(jq -r '.kata_agent.ref' "${lock}")"
    mkdir -p "${work}/kata"
    (
        cd "${work}/kata"
        "${source_dir}/hack/verify-provenance.sh" -s -a "${reference}" \
            -r "$(jq -r '.kata_agent.repository' "${lock}")" \
            -d "$(jq -r '.kata_agent.commit' "${lock}")"
        oras pull "${reference}"
        tar -I zstd -xOf "$(jq -r '.kata_agent.archive' "${lock}")" \
            "$(jq -r '.kata_agent.binary_member' "${lock}")" > kata-agent
        printf '%s  %s\n' "${expected_agent}" kata-agent | sha256sum -c -
        install -m 0755 kata-agent "${artifacts}/cache/kata-agent-${agent_version}"
    )
    agent="${artifacts}/cache/kata-agent-${agent_version}"
fi
printf '%s  %s\n' "${expected_agent}" "${agent}" | sha256sum -c -
install -D -m 0755 "${agent}" "${tree}/usr/local/bin/kata-agent"
readelf -h "${tree}/usr/local/bin/kata-agent" | grep -Eq 'Machine:[[:space:]]+Advanced Micro Devices X86-64'

pause_ref="${OPENSHELL_GUEST_PAUSE_IMAGE_REF:-$(jq -r '.pause_image.ref' "${lock}")}"
[[ "$(crane digest --platform=linux/amd64 "${pause_ref}")" == \
    "$(jq -r '.pause_image.amd64_manifest' "${lock}")" ]]
crane config --platform=linux/amd64 "${pause_ref}" >"${work}/pause-image-config.json"
jq -e '.config.Entrypoint == ["/pause"] and (.config.Cmd == null or .config.Cmd == [])' \
    "${work}/pause-image-config.json" >/dev/null
crane export --platform=linux/amd64 "${pause_ref}" "${work}/pause-rootfs.tar"
mkdir -p "${tree}/pause_bundle/rootfs"
tar -xf "${work}/pause-rootfs.tar" -C "${tree}/pause_bundle/rootfs"
(cd "${tree}/pause_bundle" && runc spec)
jq '.process.args = ["/pause"]' "${tree}/pause_bundle/config.json" \
    >"${tree}/pause_bundle/config.json.tmp"
mv "${tree}/pause_bundle/config.json.tmp" "${tree}/pause_bundle/config.json"
printf '%s  %s\n' "$(jq -r '.pause_image.binary_sha256' "${lock}")" \
    "${tree}/pause_bundle/rootfs/pause" | sha256sum -c -
jq -e '.process.args == ["/pause"]' "${tree}/pause_bundle/config.json" >/dev/null

# Upstream systemd owns AA/CDH exactly once; Kata does not start duplicates.
grep -Fx 'guest_components_procs = "none"' "${tree}/etc/agent-config.toml"
grep -Eq '^server_addr[[:space:]]*=[[:space:]]*"unix:///run/kata-containers/agent.sock"$' \
    "${tree}/etc/agent-config.toml"
for path in \
    etc/systemd/system/process-user-data.service \
    etc/systemd/system/attestation-agent.service \
    etc/systemd/system/confidential-data-hub.service \
    etc/systemd/system/kata-agent.service \
    usr/local/bin/agent-protocol-forwarder \
    usr/local/bin/process-user-data \
    usr/local/bin/attestation-agent \
    usr/local/bin/confidential-data-hub \
    usr/local/bin/kata-agent; do
    [[ -f "${tree}/${path}" && ! -L "${tree}/${path}" ]] || { echo "missing payload: ${path}" >&2; exit 1; }
done
# Git records executable bits, but private checkout umasks must not become
# permissions of these public files in the guest root filesystem.
find "${tree}" -type d -exec chmod 0755 -- {} +
find "${tree}" -type f -perm /111 -exec chmod 0755 -- {} +
find "${tree}" -type f ! -perm /111 -exec chmod 0644 -- {} +
LC_ALL=C TZ=UTC tar --sort=name --mtime=@0 --owner=0 --group=0 --numeric-owner \
    --format=posix --pax-option=delete=atime,delete=ctime \
    -cf "${archive}.tmp" -C "${tree}" .
mv -- "${archive}.tmp" "${archive}"
[[ "$(payload_inputs_sha256)" == "${input_sources_sha256}" ]] || {
    echo 'guest payload sources changed during build' >&2
    exit 1
}
sha256sum "${archive}" >"${archive}.sha256"
printf '%s\n' "${input_sources_sha256}" >"${archive%.tar}.caa-source-sha256"
printf '%s\n' "$(git -C "${source_root}" write-tree)" \
    >"${archive%.tar}.caa-tree"
printf '[guest] payload: %s\n' "${archive}"
