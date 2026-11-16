#!/usr/bin/env bash
# End-to-end Linux OCI verification script for `analyze full` on real CIP & standard trees.
# Supports Docker and rootless Podman (Linux & macOS Podman Machine); requires network access
# to kernel.org / gitlab.com and ~5 GB disk for kernel git cache.

set -euo pipefail

# Ensure Homebrew binaries (e.g. podman on macOS Apple Silicon / Intel) are discoverable.
export PATH="/opt/homebrew/bin:/usr/local/bin:${PATH}"

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
IMAGE_TAG="${IMAGE_TAG:-kernelvex:local}"
WORK_ROOT="${WORK_ROOT:-/tmp/kernelvex-full-verify}"
JOBS="${JOBS:-2}"

mkdir -p "${WORK_ROOT}"
# Canonicalize WORK_ROOT so macOS /tmp -> /private/tmp resolves to Podman Machine's /private mount.
WORK_ROOT="$(python3 -c 'import os, sys; print(os.path.realpath(sys.argv[1]))' "${WORK_ROOT}")"
CACHE_HOST="${WORK_ROOT}/cache"
SRC_HOST="${WORK_ROOT}/sources"
OUT_HOST="${WORK_ROOT}/out"

if command -v docker >/dev/null 2>&1; then
  OCI="docker"
elif command -v podman >/dev/null 2>&1; then
  OCI="podman"
else
  echo "error: docker or podman is required to run OCI full-mode verification" >&2
  exit 20
fi

# Preserve host UID ownership for rootless Podman bind mounts under container UID 10001.
OCI_RUN_ARGS=()
if [ "${OCI}" = "podman" ] && [ "$(podman info --format '{{.Host.Security.Rootless}}' 2>/dev/null || true)" = "true" ]; then
  OCI_RUN_ARGS=(--userns=keep-id:uid=10001,gid=10001)
fi

mkdir -p "${CACHE_HOST}" "${SRC_HOST}" "${OUT_HOST}"
# Allow container UID 10001 to write cached formulas and reports across Docker/Podman bind mounts,
# including subdirectories restored by actions/cache under host runner UID.
chmod 0777 "${CACHE_HOST}" "${OUT_HOST}"
chmod -R a+rwX "${CACHE_HOST}" "${OUT_HOST}"

echo "[1/6] Building OCI image ${IMAGE_TAG} using ${OCI}..."
if [ "${SKIP_BUILD:-0}" != "1" ]; then
  "${OCI}" build -t "${IMAGE_TAG}" "${ROOT_DIR}"
fi

echo "[2/6] Verifying non-root user and pinned upstream tools inside container..."
"${OCI}" run --rm "${OCI_RUN_ARGS[@]}" --entrypoint /bin/sh "${IMAGE_TAG}" -c \
  'test "$(id -u)" = "10001" && test "$(whoami)" = "kernelvex" && clang --version >/dev/null && cve-triage --version && kmaxall --help >/dev/null && kreader --help >/dev/null && kernelvex --version'

echo "[3/6] Refreshing cip-kernel-sec into /cache..."
"${OCI}" run --rm "${OCI_RUN_ARGS[@]}" -v "${CACHE_HOST}:/cache" "${IMAGE_TAG}" catalog refresh

echo "[4/6] Preparing bare blobless kernel sources and CIP reference defconfigs..."
if [ ! -d "${SRC_HOST}/cip-kernel-config/.git" ]; then
  git clone --depth 1 https://gitlab.com/cip-project/cip-kernel/cip-kernel-config.git "${SRC_HOST}/cip-kernel-config"
fi
if [ ! -d "${SRC_HOST}/linux-cip.git/objects" ]; then
  git clone --bare --filter=blob:none --single-branch --branch linux-5.10.y-cip \
    https://gitlab.com/cip-project/cip-kernel/linux-cip.git "${SRC_HOST}/linux-cip.git"
elif ! git --git-dir="${SRC_HOST}/linux-cip.git" rev-parse --verify "v5.10.224-cip52^{commit}" >/dev/null 2>&1; then
  git --git-dir="${SRC_HOST}/linux-cip.git" fetch --tags origin linux-5.10.y-cip
fi
git --git-dir="${SRC_HOST}/linux-cip.git" describe --abbrev=0 "v5.10.224-cip52^{commit}" >/dev/null

if [ ! -d "${SRC_HOST}/linux-stable.git/objects" ]; then
  git clone --bare --filter=blob:none --single-branch --branch linux-5.15.y \
    https://github.com/gregkh/linux.git "${SRC_HOST}/linux-stable.git"
elif ! git --git-dir="${SRC_HOST}/linux-stable.git" rev-parse --verify "v5.15.165^{commit}" >/dev/null 2>&1; then
  git --git-dir="${SRC_HOST}/linux-stable.git" fetch --tags origin linux-5.15.y
fi
git --git-dir="${SRC_HOST}/linux-stable.git" describe --abbrev=0 "v5.15.165^{commit}" >/dev/null

# Ensure non-read-only container runs on Linux Docker (UID 10001) can register
# detached worktrees and persist lazily fetched blobs inside bare partial mirrors.
chmod -R a+rwX "${SRC_HOST}/linux-cip.git" "${SRC_HOST}/linux-stable.git"

run_pipeline_container() {
  local src_mount_opt="$1"
  local profile="$2"
  local kernel_version="$3"
  local kernel_config="$4"
  local kernel_source="$5"
  local stable_branch="$6"
  local out_file="$7"
  local report_file="$8"
  set +e
  "${OCI}" run --rm "${OCI_RUN_ARGS[@]}" \
    -v "${CACHE_HOST}:/cache" \
    -v "${SRC_HOST}:/sources${src_mount_opt}" \
    -v "${OUT_HOST}:/out" \
    "${IMAGE_TAG}" ci pipeline \
      --profile "${profile}" \
      --kernel-version "${kernel_version}" \
      --kernel-config "${kernel_config}" \
      --kernel-source "${kernel_source}" \
      --stable-branch "${stable_branch}" \
      --mode full \
      --skip-refresh \
      --jobs "${JOBS}" \
      --cve-id CVE-2024-40901 CVE-2024-40990 CVE-2024-44958 \
      --report-out "/out/${report_file}" \
      --output "/out/${out_file}"
  local rc=$?
  set -e
  # Exit 10 (open triage) is expected when any evaluated CVE remains under_investigation.
  if [ "${rc}" -ne 0 ] && [ "${rc}" -ne 10 ]; then
    echo "error: unexpected ${profile} pipeline exit code ${rc}" >&2
    exit "${rc}"
  fi
}

echo "[5/6] Running CIP full triage (worktree + warm read-only :ro kmax run) on v5.10.224-cip52..."
if compgen -G "${CACHE_HOST}/kmax/cip-*.kmax" >/dev/null; then
  CIP_PRE_CACHED=1
else
  CIP_PRE_CACHED=0
fi
run_pipeline_container "" "cip" "v5.10.224-cip52" \
  "/sources/cip-kernel-config/5.10.y-cip/x86/cip_merged_defconfig" \
  "/sources/linux-cip.git" "cip/5.10" "cip-cold.vex.json" "cip-cold.report.json"

run_pipeline_container ":ro" "cip" "v5.10.224-cip52" \
  "/sources/cip-kernel-config/5.10.y-cip/x86/cip_merged_defconfig" \
  "/sources/linux-cip.git" "cip/5.10" "cip-warm.vex.json" "cip-warm.report.json"

"${OCI}" container prune -f >/dev/null 2>&1 || true

python3 - <<PY
import json
from pathlib import Path

cold_report = json.loads(Path("${OUT_HOST}/cip-cold.report.json").read_text())
warm_report = json.loads(Path("${OUT_HOST}/cip-warm.report.json").read_text())
vex = json.loads(Path("${OUT_HOST}/cip-warm.vex.json").read_text())

assert cold_report["meta"]["kmax_cache_hit"] is ("${CIP_PRE_CACHED}" == "1")
assert warm_report["meta"]["kmax_cache_hit"] is True
assert vex["meta"]["profile"] == "cip"
by_cve = {s["vulnerability"]["name"]: s for s in vex["statements"]}
assert by_cve["CVE-2024-40901"]["status"] == "not_affected"
assert by_cve["CVE-2024-40901"]["justification"] == "vulnerable_code_not_present"
assert "check_introduced_by_file_compiled" in by_cve["CVE-2024-40901"]["status_notes"]
assert by_cve["CVE-2024-40990"]["status"] == "fixed"
print(f"CIP full-mode assertions passed (cold={cold_report['meta']['elapsed_seconds']}s, warm={warm_report['meta']['elapsed_seconds']}s).")
PY

echo "[6/6] Running non-CIP standard full triage (worktree + warm read-only :ro kmax run) on 5.15.165..."
if compgen -G "${CACHE_HOST}/kmax/standard-*.kmax" >/dev/null; then
  STD_PRE_CACHED=1
else
  STD_PRE_CACHED=0
fi
run_pipeline_container "" "standard" "5.15.165" \
  "/sources/cip-kernel-config/5.15.y/x86/cip_merged_defconfig" \
  "/sources/linux-stable.git" "stable/5.15" "standard-cold.vex.json" "standard-cold.report.json"

run_pipeline_container ":ro" "standard" "5.15.165" \
  "/sources/cip-kernel-config/5.15.y/x86/cip_merged_defconfig" \
  "/sources/linux-stable.git" "stable/5.15" "standard-warm.vex.json" "standard-warm.report.json"

python3 - <<PY
import json
from pathlib import Path

cold_report = json.loads(Path("${OUT_HOST}/standard-cold.report.json").read_text())
warm_report = json.loads(Path("${OUT_HOST}/standard-warm.report.json").read_text())
vex = json.loads(Path("${OUT_HOST}/standard-warm.vex.json").read_text())

assert cold_report["meta"]["kmax_cache_hit"] is ("${STD_PRE_CACHED}" == "1")
assert warm_report["meta"]["kmax_cache_hit"] is True
assert vex["meta"]["profile"] == "standard"
assert vex["meta"]["stable_branch"] == "stable/5.15"
assert vex["meta"]["analysis_level"] == "full"
by_cve = {s["vulnerability"]["name"]: s for s in vex["statements"]}
assert by_cve["CVE-2024-40901"]["status"] == "not_affected"
assert by_cve["CVE-2024-40901"]["justification"] == "vulnerable_code_not_present"
assert "check_introduced_by_file_compiled" in by_cve["CVE-2024-40901"]["status_notes"]
assert by_cve["CVE-2024-40990"]["status"] == "fixed"
assert "check_fixed_by" in by_cve["CVE-2024-40990"]["status_notes"]
assert by_cve["CVE-2024-44958"]["status"] == "fixed"
assert "check_fixed_by" in by_cve["CVE-2024-44958"]["status_notes"]
print(f"Standard non-CIP full-mode assertions passed (cold={cold_report['meta']['elapsed_seconds']}s, warm={warm_report['meta']['elapsed_seconds']}s).")
PY

echo "Full Linux OCI verification succeeded. Output files in ${OUT_HOST}."
