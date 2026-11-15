# How To: Deploy KernelVEX and Audit a Linux Kernel by Version and Config

This guide walks through deploying **KernelVEX** and checking whether a Linux kernel build is impacted by CVEs using only its **kernel version** and **kernel configuration** (`.config` or `/proc/config.gz`), with optional **compile-time proof (`kmax`)** when kernel Git sources are available.

---

## Overview: What Inputs You Need

Every KernelVEX check requires at least two build artifacts:

| Input | CLI Flag | Examples | Purpose |
| :--- | :--- | :--- | :--- |
| **Kernel version** | `--kernel-version` | `6.6.60`, `v5.10.224-cip52`, `6.12.11-200.fc41.aarch64` | Determines `cip` vs `standard` profile, `stable/<X.Y>` branch, and semantic fix status |
| **Kernel config** | `--kernel-config` | `.config`, `config.gz`, `/boot/config-$(uname -r)` | Plain-text or gzipped Kconfig (automatically decompressed and SHA-256 hashed) |
| **Kernel Git tree** *(optional)* | `--kernel-source` | `/sources/linux-stable`, `/sources/linux-cip` | Required only in **`full` mode** to inspect commit ancestry and Kbuild `.o` compilation rules |
| **Kernel Git tag/SHA** *(optional)* | `--kernel-rev` | `v6.12.11`, `my-bsp-tag`, `a2de78ee6ed8` | Needed in **`full` mode** when `--kernel-version` (`uname -r`) has distro/local suffixes absent from Git tags |

### Choosing `quick` vs `full` Mode

| Mode | Required Inputs | How It Evaluates CVEs | Typical Runtime (cached) |
| :--- | :--- | :--- | :--- |
| **`quick`** | `--kernel-version` + `--kernel-config` | Checks `fixed-by` semantic versions in `cip-kernel-sec` and any cached `affected-configs` / Kconfig rules | ~1–45 s *(depends on CVE count & JSON Schema validation)* |
| **`full`** | `--kernel-version` + `--kernel-config` + `--kernel-source` | Runs upstream `cve-triage triage` + `kmax`: verifies Git commit ancestry (`merge-base`), tracks renamed/added files (`git log --follow`), and checks via `kmax` + `make alldefconfig` if vulnerable `.c`/`.h` objects are actually compiled | Seconds for a targeted CVE set; ~5–10 min for ~200 open CVEs after `.kmax` cache warmup |

> **Conservative CRA guarantee:** Any CVE that cannot be conclusively proven `fixed` or `not_affected` (`vulnerable_code_not_present`) is emitted as `under_investigation` (or `affected` with `--policy-affected`).

---

## 1. Deploying KernelVEX

### Option A — Container Image (Docker or Rootless Podman)

Building from the repository's [Dockerfile](Dockerfile) packages `kernelvex`, pinned `kernel-cve-triage` (`3aa04484d7b0e58331d3da4b2aef78376f23de55`), `kmax==4.10`, `clang`/`lld`, and GNU cross-compilers (`x86_64` and `aarch64`) under non-root user `kernelvex` (`uid=10001`, `gid=10001`).

#### Docker (Linux)

```bash
git clone <your-kernelvex-repo-url> KernelVEX
cd KernelVEX
docker build -t kernelvex:local .
docker run --rm kernelvex:local --version
```

#### Rootless Podman (Linux & macOS Podman Machine)

On rootless Podman, pass `--userns=keep-id:uid=10001,gid=10001` so the container's `kernelvex` user owns mounted volumes and output files cleanly:

```bash
podman build -t localhost/kernelvex:local .
podman run --rm --userns=keep-id:uid=10001,gid=10001 localhost/kernelvex:local --version
```

##### Recommended Podman Machine Setup on macOS (Apple Silicon / Intel)

For `full` mode on macOS, size the Linux VM with at least 4 CPUs and 6 GiB RAM, and store persistent caches/sources in **native Podman volumes** (VM XFS filesystem) rather than VirtioFS host bind mounts (measured **~5x–7x faster** on Git graph/tree lookups and `kreader` calls):

```bash
# 1. Size Podman Machine for parallel full triage (--jobs 4)
podman machine stop
podman machine set --cpus 4 --memory 6144
podman machine start

# 2. Create native VM XFS volumes for cache, kernel Git sources, and working artifacts
podman volume create kernelvex-cache
podman volume create kernelvex-sources
podman volume create kernelvex-work
```

*(If mounting host paths directly on macOS instead of named volumes, use real paths such as `$PWD/...` or `/private/tmp/...`, because `/tmp` on macOS is a symlink outside VirtioFS exports.)*

---

### Option B — Native Linux Installation (Ubuntu 24.04 / Debian)

Match the system dependencies in [Dockerfile](Dockerfile) and pins in [PINS.lock](PINS.lock):

```bash
sudo apt-get update && sudo apt-get install -y --no-install-recommends \
  ca-certificates build-essential git clang lld llvm libclang-dev clang-tools \
  gcc-x86-64-linux-gnu gcc-aarch64-linux-gnu flex bison bc libssl-dev libelf-dev \
  python3 python3-dev python3-venv

python3 -m venv /opt/kernelvex
source /opt/kernelvex/bin/activate

pip install -U "pip>=25.1" "setuptools<82" wheel
printf 'setuptools<82\n' > /tmp/build-constraints.txt
pip install --build-constraint /tmp/build-constraints.txt \
  "kmax==4.10" \
  "git+https://gitlab.com/cip-project/cip-kernel/kernel-cve-triage.git@3aa04484d7b0e58331d3da4b2aef78376f23de55"
pip install .
rm -f /tmp/build-constraints.txt

export KERNELVEX_CACHE_DIR="${PWD}/.cache/kernelvex"
kernelvex --version
```

---

## 2. Collecting the Kernel Version and Config

Extract the exact kernel version and effective configuration from your target system or build tree:

- **Running Linux host / VM / container host:**
  ```bash
  uname -r > kernel.version
  # Copy whichever exists on the target into your working directory (or /work volume):
  cp /proc/config.gz kernel.config.gz              # or:
  cp "/boot/config-$(uname -r)" kernel.config      # or:
  cp "/lib/modules/$(uname -r)/config" kernel.config
  ```
- **Podman Machine VM (macOS) into the `kernelvex-work` volume:**
  ```bash
  podman machine ssh 'uname -r'
  podman machine ssh 'cat "/lib/modules/$(uname -r)/config"' | \
    podman run --rm -i --userns=keep-id:uid=10001,gid=10001 \
      -v kernelvex-work:/work --entrypoint sh localhost/kernelvex:local \
      -c 'cat > /work/kernel.config'
  ```
- **Yocto / Buildroot / Kbuild CI output:** copy the built `.config` directly from the kernel build artifact directory.

`kernelvex` detects `.gz` magic bytes automatically, so either `/work/kernel.config` or `/work/kernel.config.gz` can be passed to `--kernel-config`.

---

## 3. Quick Check (Config + Version Only, No Kernel Sources)

Use **`quick` mode** when you only have `--kernel-version` and `--kernel-config` (for instance, auditing a distro/VM kernel, binary firmware image, or fast PR gate).

### Step 3.1 — Populate / Refresh the `cip-kernel-sec` CVE Catalog

Using Podman with native volumes:

```bash
podman run --rm --userns=keep-id:uid=10001,gid=10001 \
  -v kernelvex-cache:/cache \
  localhost/kernelvex:local \
  --cache-dir /cache catalog refresh
```

*(With Docker, omit `--userns=keep-id:uid=10001,gid=10001` and replace `localhost/kernelvex:local` with `kernelvex:local`; on native CLI run `kernelvex --cache-dir ... catalog refresh`.)*

### Step 3.2 — Run `ci pipeline --mode quick`

Example auditing kernel `6.12.11-200.fc41.aarch64` against all 2026+ CVEs (add `--skip-refresh` on subsequent runs to skip network `git pull`):

```bash
podman run --rm --userns=keep-id:uid=10001,gid=10001 \
  -v kernelvex-cache:/cache \
  -v kernelvex-work:/work \
  localhost/kernelvex:local \
  --cache-dir /cache ci pipeline \
    --mode quick \
    --profile auto \
    --kernel-version "6.12.11-200.fc41.aarch64" \
    --kernel-config /work/kernel.config \
    --cve-since-year 2026 \
    --report-out /work/report.quick.json \
    --output /work/openvex.quick.json
```

Notes:
- `--profile auto` selects `cip` when `--kernel-version` contains `-cip` or `-st` (or `--stable-branch cip/*`), and `standard` otherwise (auto-deriving `--stable-branch stable/6.12` here). For a release-candidate or mainline tree without a `stable/X.Y` branch, pass `--stable-branch mainline`.
- With default `--fail-on none`, exit code `10` is **normal** when at least one CVE remains `under_investigation` (`0` = clean, `20` = tool/input error).

---

## 4. Full Check (Compile-Time Proof with Kernel Git Sources)

Use **`full` mode** to eliminate false positives where your kernel version lacks a fix commit (or has an unmerged backport) **because the affected `.c`/`.h` source files are not compiled under your `.config`**.

### Step 4.1 — Prepare a Reusable Kernel Git Source Volume (Once)

`cve-triage` needs commit history and annotated release tags (`git describe --abbrev=0`). Rather than re-cloning on every audit, prepare a mirrored Git repository once and mount it **read-only (`:ro`)**:

```bash
# Example: mirror Linux stable + all release tags once into the kernelvex-sources volume
podman run --rm --userns=keep-id:uid=10001,gid=10001 \
  -v kernelvex-sources:/sources \
  --entrypoint sh localhost/kernelvex:local -c '
    set -eu
    git clone --mirror \
      https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git \
      /sources/linux-stable.git
    # Precompute Git commit-graph + changed-paths Bloom filters (major speedup for cve-triage)
    git -C /sources/linux-stable.git commit-graph write --reachable --changed-paths
    git -C /sources/linux-stable.git config core.commitGraph true
  '
```

*(Using `--mirror` fetches all branches, tags, and file blobs upfront and configures remote refspecs cleanly for later updates.)*

To update the local Git mirror later for a newer minor release:

```bash
podman run --rm --userns=keep-id:uid=10001,gid=10001 \
  -v kernelvex-sources:/sources \
  --entrypoint sh localhost/kernelvex:local -c '
    git -C /sources/linux-stable.git remote update --prune &&
    git -C /sources/linux-stable.git commit-graph write --reachable --changed-paths
  '
```

> **Tip if you use a `--filter=blob:none` partial clone (e.g., from a GitHub mirror):** Before mounting `:ro`, first fetch the target tag's file blobs so checkout succeeds without network (`git -C /sources/linux.git archive v6.12.11 >/dev/null`), and then pass `-e GIT_NO_LAZY_FETCH=1` on `podman run` / `docker run` during `analyze full` so Git does not attempt on-demand blob fetches across foreign branches.

### Step 4.2 — Run Single-Command `ci pipeline --mode full`

If `--kernel-version` matches the Git tag (`v5.10.224-cip52` or `5.15.165`), omit `--kernel-rev`. When auditing a distro/vendor `uname -r` string (`6.12.11-200.fc41.aarch64`), pass `--kernel-rev v6.12.11` so `git checkout` resolves the exact upstream tag:

```bash
podman run --rm --userns=keep-id:uid=10001,gid=10001 \
  -v kernelvex-cache:/cache \
  -v kernelvex-sources:/sources:ro \
  -v kernelvex-work:/work \
  localhost/kernelvex:local \
  --cache-dir /cache ci pipeline \
    --mode full \
    --skip-refresh \
    --profile auto \
    --kernel-version "6.12.11-200.fc41.aarch64" \
    --kernel-rev "v6.12.11" \
    --kernel-config /work/kernel.config \
    --kernel-source /sources/linux-stable.git \
    --jobs 4 \
    --cve-since-year 2026 \
    --report-out /work/report.full.json \
    --output /work/openvex.full.json
```

**Caching behavior:**
- **Cold run** for a `(profile, commit[:12], arch)` key runs `kmaxall` across the Linux tree and writes `/cache/kmax/<profile>-<commit12>-<arch>.kmax` (~10–15 MiB).
- **Warm runs** detect that file automatically (`kmax_cache_hit: true`) and skip `kmaxall`.
- **Cross-architecture kernels** (e.g., an `x86_64` `.config` analyzed on an `arm64` Mac host) work out of the box: `kernelvex` automatically configures `ARCH`, `CROSS_COMPILE`, or `LLVM=1`.

### Step 4.3 — Recommended Fast Two-Stage Workflow (`quick` -> `full` on Open CVEs Only)

When scanning thousands of CVEs (e.g., an entire year of Linux CVEs), `quick` already proves ~95%+ as `fixed` or `not_affected` in seconds. You can avoid running `cve-triage` Git/Kmax checks over already-fixed CVEs by feeding only the unresolved `under_investigation` subset into `analyze full` *(note: for small CVE sets or when you want a single merged OpenVEX file directly, prefer `ci pipeline --mode full` above)*:

```bash
# 1. Refresh catalog and run quick triage across the target window
podman run --rm --userns=keep-id:uid=10001,gid=10001 \
  -v kernelvex-cache:/cache \
  -v kernelvex-work:/work \
  localhost/kernelvex:local \
  --cache-dir /cache ci pipeline \
    --mode quick \
    --kernel-version "6.12.11-200.fc41.aarch64" \
    --kernel-config /work/kernel.config \
    --cve-since-year 2026 \
    --report-out /work/quick.report.json \
    --output /work/quick.vex.json || test $? -eq 10

# 2. Extract only CVEs still under_investigation
OPEN_CVES=$(podman run --rm --userns=keep-id:uid=10001,gid=10001 \
  -v kernelvex-work:/work:ro \
  --entrypoint python3 localhost/kernelvex:local -c '
import json
doc = json.load(open("/work/quick.vex.json"))
print(" ".join(s["vulnerability"]["name"] for s in doc["statements"] if s["status"] == "under_investigation"))
')

# 3. Run full kmax compile-time analysis only on unresolved CVEs, then emit OpenVEX
if [ -n "$OPEN_CVES" ]; then
  podman run --rm --userns=keep-id:uid=10001,gid=10001 \
    -v kernelvex-cache:/cache \
    -v kernelvex-sources:/sources:ro \
    -v kernelvex-work:/work \
    localhost/kernelvex:local \
    --cache-dir /cache analyze full \
      --profile auto \
      --kernel-version "6.12.11-200.fc41.aarch64" \
      --kernel-rev "v6.12.11" \
      --kernel-config /work/kernel.config \
      --kernel-source /sources/linux-stable.git \
      --jobs 4 \
      --cve-id $OPEN_CVES \
      --output /work/open-full.report.json

  podman run --rm --userns=keep-id:uid=10001,gid=10001 \
    -v kernelvex-cache:/cache:ro \
    -v kernelvex-work:/work \
    localhost/kernelvex:local \
    --cache-dir /cache vex emit \
      --profile auto \
      --kernel-version "6.12.11-200.fc41.aarch64" \
      --kernel-config /work/kernel.config \
      --report /work/open-full.report.json \
      --output /work/open-full.vex.json || test $? -eq 10
fi
```

To copy generated artifacts from the `kernelvex-work` volume back to the host directory:

```bash
podman run --rm --userns=keep-id:uid=10001,gid=10001 \
  -v kernelvex-work:/work:ro -v "$PWD/out:/out" \
  --entrypoint cp localhost/kernelvex:local \
  /work/quick.vex.json /work/open-full.vex.json /out/
```

---

## 5. Understanding Results, SBOM Linking, and CI Exit Codes

### OpenVEX Statuses & CRA Provenance

Every output VEX file is validated against OpenVEX v0.2.0 JSON Schema and records exact provenance (`sec_commit`, `kernel_config_sha256`, `kernel_source_commit`, `tooling_pins`):

| Statement `status` | Meaning | Typical `justification` / `status_notes` |
| :--- | :--- | :--- |
| `fixed` | Fix commit (`fixed-by`) is an ancestor of your kernel revision or superseded semantically | `check_fixed_by: found [...]` / `version >= fixed` |
| `not_affected` | Vulnerability commit is absent or disabled in your `.config` / `kmax` constraints | `vulnerable_code_not_present` (e.g. `no file is compiled`, `check_kconfig_quick`) |
| `under_investigation` | Code is compiled (or unproven) and no fix commit was detected on the analyzed tree *(distro backports, live bugs, or unexcluded headers)* | Lists compiled `.o` targets or check reasons |
| `affected` | Emitted instead of `under_investigation` only when `--policy-affected` is passed | Includes remediation `action_statement` |

- **SBOM PURL linking:** Pass `--product-purl "<exact-sbom-kernel-purl>"` (see [docs/sbom-purl-linking.md](docs/sbom-purl-linking.md)) so downstream tools match statements directly to your SPDX or CycloneDX kernel component.
- **Strict upstream schema:** Pass `--strict-openvex` to move KernelVEX's `meta` audit block out of the OpenVEX root into a `<output>.meta.json` sidecar.

### CI Exit Codes

| Exit Code | Meaning | Typical CI Action |
| :---: | :--- | :--- |
| **`0`** | Clean (`0` `under_investigation` and `0` `affected`) | Pass |
| **`10`** | Open triage remains (`--fail-on none`, default) | Inspect `under_investigation` items or pass advisory gate |
| **`20`** | Tool, input, Git, or JSON Schema error | Fix arguments, missing config/tags, or cache |
| **`30`** | Policy threshold breached (`--fail-on under_investigation` or `--fail-on affected`) | Block release |

---

## Further Reading

- General overview & architecture: [README.md](README.md)
- Non-CIP kernels (`kernel.org`, Yocto, vendor BSPs, distros): [docs/non-cip-kernels.md](docs/non-cip-kernels.md)
- CRA SBOM PURL alignment: [docs/sbom-purl-linking.md](docs/sbom-purl-linking.md)
