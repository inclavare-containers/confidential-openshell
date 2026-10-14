#!/usr/bin/env bash
set -euo pipefail
umask 077
export LC_ALL=C
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
lock="${root}/deployment/artifacts.lock.json"
source_root="${root}/.local/build-sources/cloud-api-adaptor"
podvm="${source_root}/src/cloud-api-adaptor/podvm"
artifacts="${root}/artifacts"
state="${root}/.local/guest-build"
integration_commit="$(git -C "${root}" rev-parse HEAD)"
guest_inputs_sha256() {
    (
        cd "${root}"
        find deployment/guest -type f ! -path '*/__pycache__/*' ! -name '*.pyc' -print0
        printf '%s\0' deployment/artifacts.lock.json
    ) | sort -z | xargs -0 sha256sum | sha256sum | cut -d' ' -f1
}
input_sources_sha256="$(guest_inputs_sha256)"
for command in docker jq python3.11 sha256sum tar git; do command -v "${command}" >/dev/null; done
jq -e '.schema == 1 and .platform == "linux/amd64" and .podvm.distribution == "ubuntu" and .podvm.tee_platform == "tdx"' "${lock}" >/dev/null
test "$(git -C "${source_root}" write-tree)" = "$(jq -r '.["cloud-api-adaptor"].result_tree' "${root}/deployment/build/sources.lock.json")"
git -C "${source_root}" diff --quiet
[[ "$(git -C "${source_root}" rev-parse HEAD)" == "$(jq -r '.podvm.commit' "${lock}")" ]]

"${root}/deployment/guest/build-payload.sh"
payload="${artifacts}/guest-payload.tar"
sha256sum -c "${payload}.sha256"
mkdir -p "${artifacts}/guest" "${artifacts}/cache/mkosi-packages" "${state}"
work="$(mktemp -d "${artifacts}/.guest-mkosi.XXXXXX")"
evidence="${state}/$(date -u +%Y%m%dT%H%M%SZ)-$$"
mkdir -p "${evidence}" "${work}/image/resources/binaries-tree"
completed=0
cleanup() {
    local rc=$?
    if (( completed )); then
        rm -rf -- "${work}"
    else
        printf 'guest build failed; diagnostic staging retained: %s\n' "${work}" >&2
    fi
    exit "${rc}"
}
trap cleanup EXIT

# These are the upstream image definitions, hooks, UKI and verity partitions.
cp -a "${podvm}/mkosi.images" "${work}/image/"
cp -a "${podvm}/mkosi.conf" "${work}/image/"
cp -a "${podvm}/mkosi.skeleton-debug" "${podvm}/mkosi.skeleton-sftp" "${work}/image/"
# Only public image input trees are normalized; build state stays private.
for skeleton in \
    "${work}/image/mkosi.images/initrd/mkosi.skeleton" \
    "${work}/image/mkosi.images/system/mkosi.skeleton" \
    "${work}/image/mkosi.skeleton-debug" "${work}/image/mkosi.skeleton-sftp"; do
    find "${skeleton}" -type d -exec chmod 0755 -- {} +
    find "${skeleton}" -type f -perm /111 -exec chmod 0755 -- {} +
    find "${skeleton}" -type f ! -perm /111 -exec chmod 0644 -- {} +
done
tar -xf "${payload}" -C "${work}/image/resources/binaries-tree"
cp "${root}/deployment/guest/mkosi.conf" \
    "${work}/image/mkosi.images/system/mkosi.conf.d/openshell.conf"

mkosi_commit="$(jq -r '.mkosi.commit' "${lock}")"
[[ "${mkosi_commit}" =~ ^[0-9a-f]{40}$ ]]
image="${OPENSHELL_MKOSI_TOOLS_IMAGE:-}"
if [[ -z "${image}" ]]; then
    image="openshell-mkosi-tools:${mkosi_commit:0:12}"
    docker build --build-arg "BASE_IMAGE=${OPENSHELL_MKOSI_TOOLS_BASE_IMAGE:-$(jq -r '.mkosi.tools_base_image' "${lock}")}" \
        --build-arg "MKOSI_COMMIT=${mkosi_commit}" -t "${image}" \
        -f "${root}/deployment/guest/Dockerfile.mkosi-tools" "${root}/deployment/guest" \
        >"${evidence}/tools-build.log" 2>&1
fi
image_id="$(docker image inspect --format '{{.Id}}' "${image}")"
[[ "${image_id}" =~ ^sha256:[0-9a-f]{64}$ ]]
# A reusable tools image is accepted only with the exact official mkosi source.
docker run --rm "${image_id}" bash -euc \
    'test "$(git -C /build/mkosi rev-parse HEAD)" = "$1"; git -C /build/mkosi diff --quiet; for tool in mkosi sfdisk mcopy veritysetup unsquashfs pesign qemu-img python3; do command -v "$tool"; done' \
    bash "${mkosi_commit}" >"${evidence}/tools-check.log" 2>&1

payload_sha="$(sha256sum "${payload}" | cut -d' ' -f1)"
recipe_sha="$(sha256sum "${root}/deployment/guest/build-image.sh" | cut -d' ' -f1)"
version="$(git -C "${root}" rev-parse --short=12 HEAD)"
# Native mkosi uses the ECS host kernel, with no nested VM and no disk mappings.
docker run --rm --privileged --network host \
    --mount "type=bind,source=${work}/image,target=/image" \
    --mount "type=bind,source=${artifacts}/cache/mkosi-packages,target=/package-cache" \
    "${image_id}" /build/mkosi/bin/mkosi --profile=production --image-version="${version}" \
    --package-cache-dir=/package-cache build >"${evidence}/mkosi.log" 2>&1
raw="${work}/image/build/system.raw"
[[ -f "${raw}" && ! -L "${raw}" ]]
cp "${work}/image/build/system.manifest" "${evidence}/distro-manifest.json"

# Independently check the final raw image before converting or publishing it.
docker run --rm --privileged \
    --mount "type=bind,source=${root}/deployment/guest,target=/source/deployment/guest,readonly" \
    --mount "type=bind,source=${lock},target=/source/deployment/artifacts.lock.json,readonly" \
    --mount "type=bind,source=${payload},target=/source/artifacts/guest-payload.tar,readonly" \
    --mount "type=bind,source=${work},target=/work" \
    --mount "type=bind,source=${evidence},target=/evidence" \
    "${image_id}" python3 /source/deployment/guest/verify-image.py \
    /work/image/build/system.raw /work/inspection /evidence \
    >"${evidence}/verify.log" 2>&1

docker run --rm --mount "type=bind,source=${work},target=/work" "${image_id}" \
    qemu-img convert -f raw -O qcow2 /work/image/build/system.raw /work/guest.qcow2
qcow_sha="$(sha256sum "${work}/guest.qcow2" | cut -d' ' -f1)"
[[ "$(git -C "${root}" rev-parse HEAD)" == "${integration_commit}" && \
   "$(guest_inputs_sha256)" == "${input_sources_sha256}" ]] || {
    echo 'guest source inputs changed during image build' >&2
    exit 1
}
final="${artifacts}/guest/openshell-guest-${qcow_sha:0:12}.qcow2"
refs="${final%.qcow2}.references.json"
[[ ! -e "${final}" && ! -e "${refs}" ]]
install -m 0600 "${work}/guest.qcow2" "${final}"
install -m 0600 "${evidence}/references.json" "${refs}"
printf '%s  %s\n' "${qcow_sha}" "${final}" >"${final}.sha256"
python3.11 - "${root}" "${evidence}" "${image_id}" "${payload_sha}" "${recipe_sha}" "${final}" "${refs}" "${input_sources_sha256}" <<'PY'
import hashlib, json, pathlib, subprocess, sys
root, evidence, image, payload_sha, recipe_sha, qcow, refs, inputs_sha = sys.argv[1:]
e = pathlib.Path(evidence)
def digest(path):
    with open(path, 'rb') as f: return hashlib.file_digest(f, 'sha256').hexdigest()
receipt = {'schema':1, 'integration_commit':subprocess.check_output(['git','-C',root,'rev-parse','HEAD'],text=True).strip(),
           'recipe_sha256':recipe_sha, 'tools_image_id':image, 'payload_sha256':payload_sha,
           'guest_inputs_sha256':inputs_sha,
           'qcow2':{'path':qcow,'sha256':digest(qcow),'bytes':pathlib.Path(qcow).stat().st_size},
           'references':{'path':refs,'sha256':digest(refs)},
           'verification':json.loads((e/'verification.json').read_text()),
           'guest_boot':'not_run; real TDX two-role and persistent workspace acceptance required'}
(e/'build.json').write_text(json.dumps(receipt,indent=2)+'\n')
PY
profile="${OPENSHELL_GUEST_MANIFEST_PROFILE:-release}"
if [[ "${profile}" == source-only ]]; then
    python3.11 "${root}/deployment/build/manifest.py" --profile source-only >"${evidence}/source-manifest.json"
else
    python3.11 "${root}/deployment/build/manifest.py" --profile "${profile}" \
        --artifact "guest-payload=${payload}" --artifact "guest-image=${final}" \
        --artifact "guest-references=${refs}" >"${evidence}/source-manifest.json"
fi
completed=1
printf '[guest] qcow2: %s\n[guest] references: %s\n[guest] receipt: %s/build.json\n' "${final}" "${refs}" "${evidence}"
