#!/usr/bin/env bash
# Reproduce patched build trees without changing any repos/ checkout or refs.
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$root"
component="${1:?usage: prepare-sources.sh cloud-api-adaptor|peerpod-ctrl|caa-csi-block-driver|kata-containers [local Kata source]}"
case "$component" in
  cloud-api-adaptor|caa-csi-block-driver) source="$root/repos/$component" ;;
  peerpod-ctrl) source="$root/repos/cloud-api-adaptor" ;;
  kata-containers) source="${2:?provide an existing pinned local Kata checkout}" ;;
  *) echo 'unsupported patch component' >&2; exit 1 ;;
esac
if [[ "$component" == peerpod-ctrl ]]; then
  test "$(jq -er '."peerpod-ctrl".source' deployment/build/sources.lock.json)" = cloud-api-adaptor
fi
base="$(jq -er --arg c "$component" '.[$c].base' deployment/build/sources.lock.json)"
expected="$(jq -er --arg c "$component" '.[$c].result_tree' deployment/build/sources.lock.json)"
destination="$root/.local/build-sources/$component"
if [[ -e "$destination" ]]; then
  test "$(git -C "$destination" rev-parse HEAD)" = "$base"
  test "$(git -C "$destination" write-tree)" = "$expected"
  git -C "$destination" diff --quiet
  printf '%s verified existing result tree %s\n' "$component" "$expected"
  exit 0
fi
git -C "$source" cat-file -e "$base^{commit}"
mkdir -p "$root/.local/build-sources"
staging=$(mktemp -d "$root/.local/build-sources/.$component.XXXXXX")
trap 'rm -rf -- "$staging"' EXIT
prepared="$staging/tree"
GIT_LFS_SKIP_SMUDGE=1 git clone --no-hardlinks --dissociate --no-checkout "$source" "$prepared"
git -C "$prepared" checkout --detach "$base"
(cd "$root/patches/$component" && sha256sum -c SHA256SUMS)
while IFS= read -r patch; do
  [[ -n "$patch" && "$patch" != \#* ]] || continue
  case "$patch" in
    ../cloud-api-adaptor/*.patch)
      [[ "$component" == peerpod-ctrl && "${patch#../cloud-api-adaptor/}" != */* ]] || exit 1 ;;
    *.patch) [[ "$patch" != */* ]] || exit 1 ;;
    *) exit 1 ;;
  esac
  git -C "$prepared" apply --index "$root/patches/$component/$patch"
done < "$root/patches/$component/series"
git -C "$prepared" diff --cached --check
test "$(git -C "$prepared" write-tree)" = "$expected"
git -C "$prepared" diff --quiet
mv -T "$prepared" "$destination"
printf '%s result tree %s\n' "$component" "$expected"
