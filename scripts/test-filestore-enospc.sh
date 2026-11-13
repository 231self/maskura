#!/usr/bin/env bash
# Real ENOSPC without filling any shared host filesystem.
set -euo pipefail
test "$(uname -s)" = Linux
root="$(mktemp -d "${TMPDIR:-/tmp}/maskura-versioning-enospc.XXXXXX")"
log="$(mktemp "${TMPDIR:-/tmp}/maskura-versioning-enospc-log.XXXXXX")"
mounted=0
cleanup() {
  if [ "$mounted" -eq 1 ]; then
    sudo -n umount "$root" || return 1
  fi
  rmdir "$root"
  rm -f "$log"
}
trap cleanup EXIT
sudo -n mount -t tmpfs -o size=8m,nodev,nosuid,noexec maskura-versioning-enospc "$root"
mounted=1
test "$(findmnt -brn -o FSTYPE --target "$root")" = tmpfs
test "$(findmnt -brn -o SIZE --target "$root")" = 8388608
sudo -n chown "$(id -u):$(id -g)" "$root"
MASKURA_VERSIONING_ENOSPC_ROOT="$root" cargo test --locked -p maskura-gateway \
  --test filestore_enospc \
  full_filesystem_keeps_exact_history_and_configuration_without_false_success \
  -- --ignored --exact --test-threads=1 | tee "$log"
grep -E '^test result: ok\. 1 passed; 0 failed; 0 ignored;' "$log"
