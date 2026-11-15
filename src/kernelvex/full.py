"""Subprocess orchestration around upstream ``cve-triage`` and ``kmax`` formulas.

Implements ``analyze full`` (wrapping ``cve-triage triage`` with isolated kernel
worktrees, ``/proc/config.gz`` decompression, ``ARG_MAX``-safe CVE arguments,
and persistent ``.kmax`` file caching) and ``enrich`` (wrapping ``cve-triage enrich``).

Upstream contracts enforced here (verified against pinned ``kernel-cve-triage``):
1. ``--kmax-formulas`` must point to a concrete ``.kmax`` *file*, never a directory,
   because upstream ``cache_manager.py`` checks ``Path(kmax_formulas).is_file()``.
2. ``KernelConfig._make_full_kconfig`` runs ``make alldefconfig`` inside the kernel
   source tree; we therefore allocate a disposable worktree (or shared clone on
   read-only CI mounts) and keep raw configs outside the tree.
3. ``git describe --abbrev=0`` is used internally by ``cve_triage.triage.git.rev_version``,
   so missing release tags are surfaced immediately with actionable remediation advice.
4. Invoking ``cve-triage`` inside a temp workspace with symlinked ``issues/`` prevents
   POSIX ``ARG_MAX`` overflow when evaluating thousands of CVEs.
"""

from __future__ import annotations

import importlib.util
import json
import logging
import os
import platform
import re
import shutil
import subprocess
import sys
import tempfile
import time
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from kernelvex import PINNED_KERNEL_CVE_TRIAGE_COMMIT, PINNED_KMAX_VERSION, KernelVexError
from kernelvex.catalog import atomic_write_json, load_catalog, read_sec_commit, select_cves
from kernelvex.kconfig import LoadedKconfig
from kernelvex.profile import ProfileConfig

logger = logging.getLogger("kernelvex.full")

_GIT_SHA_RE = re.compile(r"^[0-9a-fA-F]{40}$")

# Maps Kbuild `ARCH` values to host `platform.machine()` identifiers where native CC works.
_NATIVE_ARCH_ALIASES: dict[str, frozenset[str]] = {
    "x86": frozenset({"x86_64", "amd64", "i386", "i686"}),
    "arm64": frozenset({"aarch64", "arm64"}),
    "arm": frozenset({"armv7l", "armv6l", "arm"}),
    "riscv": frozenset({"riscv64"}),
}

# Standard Debian/Ubuntu GNU cross-toolchain prefixes keyed by Kbuild `ARCH`.
_CROSS_COMPILE_PREFIXES: dict[str, str] = {
    "x86": "x86_64-linux-gnu-",
    "arm64": "aarch64-linux-gnu-",
    "arm": "arm-linux-gnueabihf-",
    "riscv": "riscv64-linux-gnu-",
    "powerpc": "powerpc64le-linux-gnu-",
    "s390": "s390x-linux-gnu-",
}


def _configure_kbuild_env(base_env: Mapping[str, str], make_arch: str) -> dict[str, str]:
    """Configure ``ARCH`` and cross-compiler environment variables for Kbuild/Kmax.

    Respects explicit caller ``ARCH``, ``CROSS_COMPILE``, ``CC``, or ``LLVM`` settings.
    When evaluating a foreign kernel architecture (such as ``x86`` inside an ``arm64``
    container or ``arm64`` on an ``x86_64`` CI runner), selects the matching GNU
    ``CROSS_COMPILE`` prefix if installed, or falls back to ``LLVM=1`` when both
    ``clang`` and ``ld.lld`` are available.

    Args:
        base_env: Baseline environment mapping (typically ``os.environ``).
        make_arch: Target Kbuild ``ARCH`` derived from ``.config``.

    Returns:
        Mutable environment copy ready for ``subprocess.run(..., env=...)``.
    """
    env = dict(base_env)
    env.setdefault("ARCH", make_arch)

    # Never override explicit cross-compilation variables provided by caller CI pipelines.
    if any(var in env for var in ("CROSS_COMPILE", "CC", "LLVM")):
        return env

    # Native architectures compile Kconfig scripts and headers directly with host gcc.
    host_machine = platform.machine().lower()
    if host_machine in _NATIVE_ARCH_ALIASES.get(make_arch, frozenset()):
        return env

    # Foreign kernel architecture: prefer GNU cross-compiler, otherwise LLVM=1 (clang+lld).
    prefix = _CROSS_COMPILE_PREFIXES.get(make_arch)
    if prefix and shutil.which(f"{prefix}gcc"):
        env["CROSS_COMPILE"] = prefix
    elif shutil.which("clang") and shutil.which("ld.lld"):
        env["LLVM"] = "1"
    return env


def _find_cve_triage_bin(override: str | None = None) -> str:
    """Locate the ``cve-triage`` executable or raise ``KernelVexError`` (exit 20).

    Args:
        override: Optional explicit binary path or executable name.

    Returns:
        Resolved executable path verified with ``os.X_OK``.

    Raises:
        KernelVexError: If ``cve-triage`` cannot be located on ``PATH`` or is not executable.
    """
    candidate = override or shutil.which("cve-triage")
    if candidate is None:
        raise KernelVexError("Required binary 'cve-triage' (kernel-cve-triage) not found on PATH")
    resolved = shutil.which(candidate) if os.sep not in candidate else candidate
    if resolved is None or not os.access(resolved, os.X_OK):
        raise KernelVexError(f"Executable 'cve-triage' is not runnable: {candidate!r}")
    return resolved


def _can_use_inprocess_accel() -> bool:
    """Return ``True`` when pinned ``cve_triage`` and ``kmax`` packages are importable.

    Used as a capability probe without importing Z3 prematurely in parent processes.
    """
    return (
        importlib.util.find_spec("cve_triage") is not None
        and importlib.util.find_spec("kmax") is not None
    )


def _git_output(repo: Path, args: list[str]) -> str:
    """Execute ``git -C <repo>`` and return stripped stdout or raise ``KernelVexError``.

    Args:
        repo: Kernel git checkout root directory.
        args: Arguments appended after ``git -C <repo>``.

    Returns:
        Stripped stdout returned by git.

    Raises:
        KernelVexError: If git fails to spawn or exits with a non-zero code.
    """
    cmd = ["git", "-C", str(repo), *args]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
    except OSError as exc:
        raise KernelVexError(f"Failed to run git on {repo}: {exc}") from exc
    if proc.returncode != 0:
        detail = proc.stderr.strip() or proc.stdout.strip() or f"exit code {proc.returncode}"
        raise KernelVexError(f"git failed in {repo} ({' '.join(args)}): {detail}")
    return proc.stdout.strip()


def resolve_kernel_source_commit(
    kernel_source: Path, kernel_version: str, kernel_rev: str | None = None
) -> tuple[str, str]:
    """Resolve target kernel revision label and 40-char commit SHA in ``kernel_source``.

    Tries explicit ``kernel_rev`` first; otherwise probes exact ``kernel_version``,
    ``v``-prefixed tag, ``v``-stripped tag, and ``HEAD`` before validating that
    ``git describe --abbrev=0`` succeeds (required by ``cve_triage.triage.git``).

    Args:
        kernel_source: Path to the local kernel git checkout.
        kernel_version: Target kernel version or tag from CI/CLI inputs.
        kernel_rev: Optional explicit git revision overriding ``kernel_version``.

    Returns:
        Tuple ``(matched_rev_label, full_40char_commit_sha)``.

    Raises:
        KernelVexError: If ``kernel_source`` is not a git repo, the revision cannot
            be resolved, or annotated release tags required by ``cve-triage`` are absent.
    """
    # Verify the underlying directory is actually a valid git checkout first.
    if not kernel_source.is_dir():
        raise KernelVexError(f"kernel_source directory does not exist: {kernel_source}")

    # Confirm the directory is a valid git repository before checking revisions.
    _git_output(kernel_source, ["rev-parse", "--git-dir"])

    if kernel_rev:
        candidates = [kernel_rev]
    else:
        stripped = kernel_version.strip()
        # Probe both raw and v-prefixed git tag spellings before falling back to HEAD
        # because `uname -r` drops the leading `v` while CIP/kernel.org git tags keep it.
        candidates = list(
            dict.fromkeys([stripped, f"v{stripped.lstrip('v')}", stripped.lstrip("v"), "HEAD"])
        )

    matched_rev: str | None = None
    commit_sha: str | None = None
    for candidate in candidates:
        # Use ^{commit} so annotated tags resolve directly to their underlying commit SHA
        # instead of returning the tag object SHA itself.
        proc = subprocess.run(
            ["git", "-C", str(kernel_source), "rev-parse", "--verify", f"{candidate}^{{commit}}"],
            capture_output=True,
            text=True,
            check=False,
        )
        if proc.returncode == 0:
            matched_rev = candidate
            commit_sha = proc.stdout.strip().lower()
            break

    if matched_rev is None or commit_sha is None or not _GIT_SHA_RE.match(commit_sha):
        raise KernelVexError(
            f"Unable to resolve kernel revision for {kernel_version!r} in {kernel_source}"
        )

    # Upstream cve-triage invokes `git describe --abbrev=0 <rev>` without --tags.
    # Catch shallow or tagless checkouts upfront with a clear diagnostic message
    # rather than failing cryptically mid-run inside kmax initialization.
    desc = subprocess.run(
        ["git", "-C", str(kernel_source), "describe", "--abbrev=0", matched_rev],
        capture_output=True,
        text=True,
        check=False,
    )
    if desc.returncode != 0:
        raise KernelVexError(
            f"kernel_source {kernel_source} is missing git tags required by cve-triage "
            f"(`git describe --abbrev=0 {matched_rev}` failed; run `git fetch --tags`)"
        )

    return (matched_rev, commit_sha)


def resolve_kmax_cache_file(
    cache_dir: Path,
    profile: str,
    kernel_source_commit: str,
    kernel_arch: str,
    explicit_kmax_formulas: Path | None = None,
) -> Path:
    """Compute a concrete ``.kmax`` file path (never a directory) for upstream caching.

    Keying by ``(profile, commit[:12], arch)`` lets multiple pipelines share one
    ``/cache/kmax`` volume without overwriting formulas across architectures or trees.
    Validates explicitly that the target path is not an existing directory because
    ``cve_triage.triage.cache_manager`` asserts ``is_file()`` on cache hits and
    attempts to pickle-write directly to that path on cold runs.

    Args:
        cache_dir: Persistent ``kernelvex`` cache directory.
        profile: Active ``"cip"`` or ``"standard"`` profile name.
        kernel_source_commit: Resolved 40-char git commit SHA of the kernel tree.
        kernel_arch: Inferred target architecture (e.g. ``x86_64``, ``aarch64``).
        explicit_kmax_formulas: Optional user-provided ``.kmax`` file override.

    Returns:
        Resolved file ``Path`` whose parent directory exists.

    Raises:
        KernelVexError: If ``explicit_kmax_formulas`` points to an existing directory.
    """
    if explicit_kmax_formulas is not None:
        resolved = explicit_kmax_formulas.expanduser().resolve()
    else:
        filename = f"{profile}-{kernel_source_commit[:12]}-{kernel_arch}.kmax"
        resolved = (cache_dir / "kmax" / filename).resolve()

    # Guard against directory paths because cve-triage requires a pickle file path.
    if resolved.exists() and resolved.is_dir():
        raise KernelVexError(
            f"--kmax-formulas must be a file path, not an existing directory: {resolved}"
        )
    resolved.parent.mkdir(parents=True, exist_ok=True)
    return resolved


def _prepare_isolated_checkout(
    kernel_source: Path, commit_sha: str, wt_dir: Path
) -> tuple[bool, Path]:
    """Create a disposable writable kernel checkout so ``make alldefconfig`` stays isolated.

    Tries ``git worktree add --detach`` first (near-instant, zero object copy) and
    falls back to ``git clone --shared`` if ``kernel_source`` is mounted read-only
    in CI containers (e.g. ``-v /src:/sources:ro``), preventing source tree mutation.
    ``git clone --shared`` creates an alternates reference to ``kernel_source/.git/objects``
    without duplicating packfiles, keeping cold setups under a second even for large
    full Linux kernel clones.

    Args:
        kernel_source: Original kernel git checkout path.
        commit_sha: Exact target commit SHA to check out detached.
        wt_dir: Temporary directory destination inside working scratch space.

    Returns:
        Tuple ``(used_worktree, checkout_dir)`` so cleanup only calls
        ``git worktree remove`` when a worktree was registered on the source repo.

    Raises:
        KernelVexError: If both ``git worktree add`` and ``git clone --shared`` fail.
    """
    # Primary path: zero-copy detached worktree inside temporary scratch workspace.
    proc = subprocess.run(
        ["git", "-C", str(kernel_source), "worktree", "add", "--detach", str(wt_dir), commit_sha],
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode == 0:
        return (True, wt_dir)

    # Fall back to shared local clone when source mount is read-only or bare-locked.
    clone_proc = subprocess.run(
        ["git", "clone", "--shared", "--no-checkout", str(kernel_source), str(wt_dir)],
        capture_output=True,
        text=True,
        check=False,
    )
    if clone_proc.returncode != 0:
        detail = clone_proc.stderr.strip() or proc.stderr.strip()
        raise KernelVexError(f"Failed to prepare isolated kernel checkout at {wt_dir}: {detail}")

    # Check out exact target SHA detached inside the writable clone before invoking make.
    _git_output(wt_dir, ["checkout", "--detach", commit_sha])
    return (False, wt_dir)


def run_full_analysis(
    cache_dir: Path,
    kernel_source: Path,
    kconfig: LoadedKconfig,
    profile_cfg: ProfileConfig,
    kernel_rev: str | None = None,
    since_year: int | None = None,
    cve_ids: list[str] | None = None,
    jobs: int = 8,
    kmax_formulas: Path | None = None,
    experimental_checks: bool = False,
    cve_triage_bin: str | None = None,
    raw_report_out: Path | None = None,
    no_accel: bool = False,
) -> dict[str, Any]:
    """Execute ``cve-triage triage`` with persistent kmax formula cache and audit trail.

    Wraps upstream ``cve-triage triage`` without reimplementing Kbuild analysis or
    commit ancestry checks. Injects ``ARCH`` inferred from ``kconfig``, passes
    ``--cip`` exclusively for CIP profiles, persists ``.kmax`` formulas across CI
    runs, and attaches exact ``sec_commit`` and ``kernel_source_commit`` digests.

    Args:
        cache_dir: Persistent cache root holding ``cip-kernel-sec`` and ``kmax/``.
        kernel_source: Local git checkout matching the built kernel revision.
        kconfig: Parsed effective kernel configuration (plain or gzip-decompressed).
        profile_cfg: Active ``cip`` or ``standard`` profile configuration.
        kernel_rev: Optional git revision overriding ``profile_cfg.parsed_version.raw``.
        since_year: Optional lower bound on CVE year passed via YAML file filtering.
        cve_ids: Optional explicit list of CVE identifiers.
        jobs: Parallel worker count forwarded to ``cve-triage triage --jobs``.
        kmax_formulas: Optional explicit path to persistent ``.kmax`` formula cache file.
        experimental_checks: Forward ``--experimental-checks`` (line-level proof).
        cve_triage_bin: Optional path to ``cve-triage`` executable override.
        raw_report_out: Optional file path to save unmodified upstream array JSON.
        no_accel: Disable in-process ``kernelvex.accel`` hooks even when available.

    Returns:
        ``kernelvex`` report envelope dict with ``meta`` and raw ``reports`` list.

    Raises:
        KernelVexError: On invalid options, missing catalog/tags, or ``cve-triage`` failure.
    """
    if jobs < 1:
        raise KernelVexError(f"--jobs must be >= 1, got {jobs}")

    # Prefer in-process accelerator module when running in the full container environment
    # without an explicit --cve-triage-bin override or --no-accel fallback flag.
    use_accel = not no_accel and cve_triage_bin is None and _can_use_inprocess_accel()
    if use_accel:
        triage_bin = sys.executable
    else:
        # Validate external prerequisites before copying configs or spawning git worktrees.
        triage_bin = _find_cve_triage_bin(cve_triage_bin)
    catalog = load_catalog(cache_dir)
    sec_dir = (cache_dir / "cip-kernel-sec").resolve()
    sec_issues_dir = sec_dir / "issues"
    if not sec_issues_dir.is_dir():
        raise KernelVexError(
            f"Missing cip-kernel-sec issues directory at {sec_issues_dir}. "
            "Run 'kernelvex catalog refresh' first."
        )

    # Bind report provenance to exact cached cip-kernel-sec HEAD and filtered CVE set.
    # select_cves() fails closed with KernelVexError if zero CVEs match, guaranteeing
    # non-empty positional YAML arguments for upstream `cve-triage triage`.
    sec_commit = read_sec_commit(cache_dir) or catalog["sec_commit"]
    selected = select_cves(
        catalog,
        profile=profile_cfg.profile,
        since_year=since_year,
        cve_ids=cve_ids,
    )

    # Resolve kernel revision and deterministic architecture/commit-keyed .kmax cache file.
    rev_label, kernel_source_commit = resolve_kernel_source_commit(
        kernel_source.resolve(), profile_cfg.parsed_version.raw, kernel_rev
    )
    kmax_cache_file = resolve_kmax_cache_file(
        cache_dir=cache_dir,
        profile=profile_cfg.profile,
        kernel_source_commit=kernel_source_commit,
        kernel_arch=kconfig.detected_arch,
        explicit_kmax_formulas=kmax_formulas,
    )
    # Record whether a pre-existing non-empty .kmax file accelerated this CI run.
    cache_hit = kmax_cache_file.is_file() and kmax_cache_file.stat().st_size > 0

    start_ts = time.monotonic()
    raw_reports = _invoke_cve_triage_triage(
        triage_bin=triage_bin,
        sec_issues_dir=sec_issues_dir,
        selected=selected,
        kernel_source=kernel_source.resolve(),
        rev_label=rev_label,
        kernel_source_commit=kernel_source_commit,
        kconfig=kconfig,
        profile_cfg=profile_cfg,
        jobs=jobs,
        kmax_cache_file=kmax_cache_file,
        cache_hit=cache_hit,
        experimental_checks=experimental_checks,
        use_accel=use_accel,
    )

    elapsed_s = round(time.monotonic() - start_ts, 3)

    # Optionally archive unmodified upstream report array before wrapping in audit meta.
    if raw_report_out is not None:
        atomic_write_json(raw_report_out, raw_reports)

    # Wrap raw report array with full cryptographic & tooling provenance for downstream vex emit.
    return {
        "meta": {
            "analysis_level": "full",
            "profile": profile_cfg.profile,
            "stable_branch": profile_cfg.stable_branch,
            "kernel_version": profile_cfg.parsed_version.raw,
            "kernel_arch": kconfig.detected_arch,
            "kernel_config_sha256": kconfig.raw_bytes_sha256,
            "sec_commit": sec_commit,
            "kernel_source_commit": kernel_source_commit,
            "kmax_cache_hit": cache_hit,
            "kmax_cache_file": str(kmax_cache_file),
            "accel_enabled": use_accel,
            "elapsed_seconds": elapsed_s,
            "tooling_pins": {
                "kernel_cve_triage": PINNED_KERNEL_CVE_TRIAGE_COMMIT,
                "kmax": PINNED_KMAX_VERSION,
            },
        },
        "reports": raw_reports,
    }


def _invoke_cve_triage_triage(
    *,
    triage_bin: str,
    sec_issues_dir: Path,
    selected: list[dict[str, Any]],
    kernel_source: Path,
    rev_label: str,
    kernel_source_commit: str,
    kconfig: LoadedKconfig,
    profile_cfg: ProfileConfig,
    jobs: int,
    kmax_cache_file: Path,
    cache_hit: bool,
    experimental_checks: bool,
    use_accel: bool = False,
) -> list[Any]:
    """Run upstream ``cve-triage triage`` in an isolated temporary workspace.

    Creates a disposable git checkout, writes the decompressed ``input.config`` outside
    the repository, symlinks ``issues/`` to avoid hitting OS ``ARG_MAX`` limits, runs
    ``cve-triage triage``, and always prunes any registered git worktree afterward.

    Args:
        triage_bin: Resolved ``cve-triage`` executable path.
        sec_issues_dir: Cached ``cip-kernel-sec/issues`` directory.
        selected: Filtered CVE catalog records containing ``yaml_relpath``.
        kernel_source: Resolved local kernel git checkout.
        rev_label: Matched git tag/revision label passed to ``-s``.
        kernel_source_commit: Exact 40-char commit SHA checked out detached.
        kconfig: Loaded plain-text kernel configuration and inferred ``ARCH``.
        profile_cfg: Active CIP or standard profile configuration.
        jobs: Worker concurrency passed via ``--jobs``.
        kmax_cache_file: Concrete persistent ``.kmax`` formula pickle file path.
        cache_hit: Whether ``kmax_cache_file`` existed before this invocation.
        experimental_checks: Forward ``--experimental-checks`` when enabled.
        use_accel: Execute ``cve_triage`` through ``python -m kernelvex.accel``.

    Returns:
        Validated JSON array decoded from upstream ``cve-triage --out``.

    Raises:
        KernelVexError: If ``cve-triage`` fails or writes non-array/invalid JSON.
    """
    # Run inside a self-cleaning TemporaryDirectory so .config, symlinks, and worktrees
    # leave zero artifacts behind on either success or exception.
    with tempfile.TemporaryDirectory(prefix="kernelvex-full-") as tmp_str:
        tmp_path = Path(tmp_str)
        wt_dir = tmp_path / "kernel-wt"
        used_worktree, checkout_dir = _prepare_isolated_checkout(
            kernel_source, kernel_source_commit, wt_dir
        )

        try:
            # Write plain-text .config outside repo so /proc/config.gz works cleanly
            # without leaving untracked artifacts inside the kernel checkout.
            input_cfg = tmp_path / "input.config"
            input_cfg.write_text(kconfig.plain_text, encoding="utf-8")

            # Symlink issues dir so relative YAML args stay short (~22 chars each),
            # keeping total argv size safely below Linux/macOS ARG_MAX on full scans.
            (tmp_path / "issues").symlink_to(sec_issues_dir)
            cve_args = [rec["yaml_relpath"] for rec in selected]
            raw_out = tmp_path / "raw_report.json"

            # Assemble exact upstream CLI contract:
            # - When accelerated hooks are enabled, launch python -m kernelvex.accel.
            # - Pass `--cip` exclusively for CIP profiles so standard trees skip CIP branches.
            # - Pass `--no-clone` because kernelvex already resolves and isolates checkout_dir.
            # - Persist `--kmax-formulas` as a concrete file path cached across CI builds.
            # - Inject isolated checkout path + resolved git ref and external input.config.
            runner_prefix = [triage_bin, "-m", "kernelvex.accel"] if use_accel else [triage_bin]
            cmd = [
                *runner_prefix,
                "triage",
                *(["--cip"] if profile_cfg.use_cip_flag else []),
                "--no-clone",
                "--jobs",
                str(jobs),
                "--kmax-formulas",
                str(kmax_cache_file),
                "-s",
                f"{checkout_dir}:{rev_label}",
                "--config",
                str(input_cfg),
                "--out",
                str(raw_out),
                *(["--experimental-checks"] if experimental_checks else []),
                *cve_args,
            ]

            # Respect caller ARCH/CROSS_COMPILE/CC/LLVM overrides; otherwise set ARCH and
            # auto-configure cross-compilation when analyzing a foreign kernel architecture.
            env = _configure_kbuild_env(os.environ, kconfig.make_arch)

            logger.info(
                "Invoking cve-triage full analysis",
                extra={
                    "profile": profile_cfg.profile,
                    "rev": rev_label,
                    "cve_count": len(cve_args),
                    "kmax_cache_hit": cache_hit,
                    "kmax_cache_file": str(kmax_cache_file),
                    "accel_enabled": use_accel,
                },
            )
            proc = subprocess.run(cmd, cwd=tmp_path, env=env, capture_output=True, text=True)
            if proc.returncode != 0 or not raw_out.is_file():
                # Surface the final lines of upstream stderr to ease CI diagnosis.
                stderr_tail = "\n".join(proc.stderr.splitlines()[-20:])
                raise KernelVexError(
                    f"cve-triage triage failed (exit {proc.returncode}): {stderr_tail}"
                )

            try:
                raw_reports = json.loads(raw_out.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError) as exc:
                raise KernelVexError(f"Failed to parse cve-triage report JSON: {exc}") from exc
        finally:
            if used_worktree:
                # Prune worktree registration from source repo so repeated CI runs stay clean
                # even when cve-triage aborted mid-run inside the temporary scratch dir.
                subprocess.run(
                    [
                        "git",
                        "-C",
                        str(kernel_source),
                        "worktree",
                        "remove",
                        "--force",
                        str(wt_dir),
                    ],
                    capture_output=True,
                    text=True,
                    check=False,
                )

    if not isinstance(raw_reports, list):
        raise KernelVexError("Expected JSON array output from cve-triage triage")
    return raw_reports


def run_enrich_wrapper(
    cache_dir: Path,
    kernel_source: Path,
    versions: list[str],
    out_dir: Path,
    cip: bool = True,
    since_year: int | None = None,
    cve_ids: list[str] | None = None,
    kmax_formulas: Path | None = None,
    cve_triage_bin: str | None = None,
) -> Path:
    """Wrap ``cve-triage enrich`` to produce enriched CVE YAML files for ``merge-enrich``.

    Executes upstream Kconfig formula extraction for one or more branch revisions
    and writes per-CVE YAML files into ``out_dir``, using relative ``issues/`` paths
    to avoid command-line length overflow.

    Args:
        cache_dir: Persistent cache containing ``cip-kernel-sec/issues``.
        kernel_source: Local git repository containing target branches/commits.
        versions: Kernel branch/tag targets forwarded via ``--versions``.
        out_dir: Destination directory for enriched CVE YAML outputs.
        cip: Pass ``--cip`` to ``cve-triage enrich`` when targeting CIP branches.
        since_year: Optional inclusive lower bound on CVE year.
        cve_ids: Optional explicit CVE list.
        kmax_formulas: Optional path to prebuilt ``.kmax`` formula cache file.
        cve_triage_bin: Optional path overriding ``cve-triage`` binary lookup.

    Returns:
        Resolved ``out_dir`` path containing generated YAML files.

    Raises:
        KernelVexError: On invalid inputs, missing catalog, or ``cve-triage`` exit error.
    """
    # Fail early on empty branch lists or missing local kernel repositories.
    if not versions:
        raise KernelVexError("At least one --versions branch (e.g. v5.10 v6.12) is required")
    if not kernel_source.is_dir():
        raise KernelVexError(f"kernel_source directory does not exist: {kernel_source}")

    # Resolve backend executable and cached cip-kernel-sec YAML selection.
    triage_bin = _find_cve_triage_bin(cve_triage_bin)
    catalog = load_catalog(cache_dir)
    sec_issues_dir = (cache_dir / "cip-kernel-sec" / "issues").resolve()
    if not sec_issues_dir.is_dir():
        raise KernelVexError(f"Missing cip-kernel-sec issues directory at {sec_issues_dir}")

    # Apply standard vs CIP filtering before generating YAML paths for enrich.
    # select_cves() raises KernelVexError on empty matches, ensuring non-empty positional args.
    selected = select_cves(
        catalog,
        profile="cip" if cip else "standard",
        since_year=since_year,
        cve_ids=cve_ids,
    )
    resolved_out = out_dir.expanduser().resolve()
    resolved_out.mkdir(parents=True, exist_ok=True)

    # Execute cve-triage inside a temporary workspace owning the short `issues/` symlink.
    with tempfile.TemporaryDirectory(prefix="kernelvex-enrich-") as tmp_str:
        tmp_path = Path(tmp_str)
        # Symlink issues dir to keep relative CVE paths compact on large selections.
        (tmp_path / "issues").symlink_to(sec_issues_dir)
        cve_args = [rec["yaml_relpath"] for rec in selected]

        # Terminate options with `--` before positional YAML paths per upstream parser.
        cmd = [
            triage_bin,
            "enrich",
            *(["--cip"] if cip else []),
            *(["--kmax-formulas", str(kmax_formulas.resolve())] if kmax_formulas else []),
            "-s",
            str(kernel_source.resolve()),
            "--versions",
            *versions,
            "--out-dir",
            str(resolved_out),
            "--",
            *cve_args,
        ]
        # Preserve only the tail of stderr when upstream enrich aborts to avoid log flooding.
        proc = subprocess.run(cmd, cwd=tmp_path, capture_output=True, text=True)
        if proc.returncode != 0:
            stderr_tail = "\n".join(proc.stderr.splitlines()[-20:])
            raise KernelVexError(
                f"cve-triage enrich failed (exit {proc.returncode}): {stderr_tail}"
            )

    return resolved_out
