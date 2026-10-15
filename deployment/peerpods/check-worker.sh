#!/usr/bin/env bash
usage='Usage: bash deployment/peerpods/check-worker.sh
Read back the effective Kata profile over WORKER_SSH. Set CONTAINERD_CONFIG if needed.'
source "$(dirname "${BASH_SOURCE[0]}")/../lib/common.sh"
need ssh python3
: "${WORKER_SSH:?export WORKER_SSH with an existing worker SSH alias}"
CONTAINERD_CONFIG=${CONTAINERD_CONFIG:-/etc/containerd/config.toml}
[[ $WORKER_SSH =~ ^[A-Za-z0-9_.@-]+$ && $CONTAINERD_CONFIG =~ ^/[A-Za-z0-9_./-]+$ ]] || die 'Invalid worker or configuration path'
WORKER_EVIDENCE="$OPERATOR_DIR/worker-profile/$WORKER_SSH"
install -d -m 0700 "$WORKER_EVIDENCE"
ssh "$WORKER_SSH" "sudo containerd --config '$CONTAINERD_CONFIG' config dump" \
  > "$WORKER_EVIDENCE/containerd.effective.before.toml"
KATA_REMOTE_CONFIG=$(python3 - "$WORKER_EVIDENCE/containerd.effective.before.toml" <<'PYCONFIG'
import pathlib, re, sys, tomllib
with open(sys.argv[1], 'rb') as f:
    merged = tomllib.load(f)
handler = merged['plugins']['io.containerd.cri.v1.runtime']['containerd']['runtimes']['kata-remote']
path = handler['options']['ConfigPath']
assert re.fullmatch(r'/opt/kata/[A-Za-z0-9_./-]+/configuration-remote\.toml', path)
assert '..' not in pathlib.PurePosixPath(path).parts
print(path)
PYCONFIG
)
printf '%s\n' "$KATA_REMOTE_CONFIG" > "$WORKER_EVIDENCE/effective-kata-config-path.txt"
printf 'Effective Kata configuration: %s\n' "$KATA_REMOTE_CONFIG"
ssh "$WORKER_SSH" "sudo cat '$KATA_REMOTE_CONFIG'" > "$WORKER_EVIDENCE/kata.before.toml"
ssh "$WORKER_SSH" 'sudo systemctl is-active --quiet containerd.service'
ssh "$WORKER_SSH" "sudo containerd --config '$CONTAINERD_CONFIG' config dump" \
  > "$WORKER_EVIDENCE/containerd.effective.after.toml"
ssh "$WORKER_SSH" "sudo cat '$KATA_REMOTE_CONFIG'" > "$WORKER_EVIDENCE/kata.after.toml"
python3 - "$WORKER_EVIDENCE" "$KATA_REMOTE_CONFIG" <<'PYCONFIG'
import pathlib, sys, tomllib
area, expected = pathlib.Path(sys.argv[1]), sys.argv[2]
with (area/'containerd.effective.after.toml').open('rb') as f:
    merged = tomllib.load(f)
assert merged['version'] in (3, 4)
handler = merged['plugins']['io.containerd.cri.v1.runtime']['containerd']['runtimes']['kata-remote']
assert handler['options']['ConfigPath'] == expected
with (area/'kata.after.toml').open('rb') as f:
    kata = tomllib.load(f)
assert kata['hypervisor']['remote']['shared_fs'] == 'none'
assert kata['runtime']['experimental_force_guest_pull'] is True
assert kata['runtime']['create_container_timeout'] == 600
PYCONFIG
sha256sum "$WORKER_EVIDENCE"/*.toml > "$WORKER_EVIDENCE/profile.sha256"
expected=$(cut -d ' ' -f1 "$OPERATOR_DIR/shim.sha256")
observed=$(ssh "$WORKER_SSH" 'sudo sha256sum /opt/kata/bin/containerd-shim-kata-v2' | cut -d ' ' -f1)
[[ $expected == "$observed" ]] || die 'Installed worker shim checksum differs from the handoff.'

printf 'Worker profile verified: %s\n' "$WORKER_EVIDENCE"
