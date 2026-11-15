"""End-to-end CI pipeline orchestration combining catalog, triage, VEX, and policy.

Coordinates ``catalog refresh``, optional ``merge-enrich``, ``analyze quick`` or
``analyze full``, OpenVEX emission, optional sidecar/raw report archiving, and
deterministic CI exit code selection (0, 10, 20, 30).

Architecture boundaries:
- Preserves ``cip-kernel-sec`` as the sole vulnerability catalog source of truth.
- Supports air-gapped runners via ``skip_refresh=True`` once ``/cache`` is populated.
- Separates policy breach exit codes (``30``) from open triage findings (``10``)
  so teams can run advisory scans alongside hard release-gate jobs using one binary.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from kernelvex import DEFAULT_SEC_BRANCH, DEFAULT_SEC_REPO_URL, KernelVexError
from kernelvex.catalog import atomic_write_json, load_catalog, refresh_catalog
from kernelvex.full import run_full_analysis
from kernelvex.kconfig import load_kconfig
from kernelvex.openvex import emit_openvex, evaluate_policy_exit_code
from kernelvex.profile import resolve_profile
from kernelvex.quick import run_quick_analysis

logger = logging.getLogger("kernelvex.pipeline")


@dataclass(frozen=True)
class PipelineOptions:
    """Validated configuration bundle for ``kernelvex ci pipeline``.

    Attributes:
        cache_dir: Persistent cache root storing ``cip-kernel-sec`` and ``.kmax`` files.
        kernel_version: Target kernel version or tag (e.g. ``v5.10.224-cip52``).
        kernel_config: Path to effective ``.config`` or ``/proc/config.gz`` export.
        output: Destination path for the emitted OpenVEX v0.2.0 JSON document.
        profile: Profile selector (``"auto"``, ``"cip"``, or ``"standard"``).
        stable_branch: Explicit ``cip-kernel-sec`` branch key overriding default derivation.
        mode: Analysis mode (``"full"`` for compile-time proof, ``"quick"`` otherwise).
        kernel_source: Path to complete git checkout required when ``mode == "full"``.
        kernel_rev: Optional git revision override when tag differs from ``kernel_version``.
        sec_url: Git remote URL for ``cip-kernel-sec`` synchronization.
        sec_ref: Git branch, tag, or SHA in ``cip-kernel-sec`` to evaluate against.
        skip_refresh: When ``True``, reuse cached ``catalog.json`` without network fetch.
        since_year: Inclusive lower bound filtering evaluated CVE years (e.g. ``2024``).
        cve_ids: Optional explicit CVE allowlist overriding year-based selection.
        jobs: Worker concurrency passed to ``cve-triage triage --jobs``.
        kmax_formulas: Optional explicit ``.kmax`` cache file overriding auto-naming.
        experimental_checks: Enable upstream line-level checks in ``cve-triage triage``.
        cve_triage_bin: Explicit path to ``cve-triage`` binary overriding ``PATH`` lookup.
        no_accel: Disable in-process ``kernelvex.accel`` hooks and invoke raw ``cve-triage``.
        author: OpenVEX document ``author`` metadata field.
        role: OpenVEX author ``role`` metadata field.
        doc_id: Explicit OpenVEX ``@id`` IRI overriding deterministic generation.
        kernel_url: Upstream kernel repository URL used to derive product PURLs.
        kernel_arch: Explicit PURL architecture override when omitted from Kconfig.
        product_purl: Explicit SBOM product PURL bypassing URL inference.
        timestamp: Explicit RFC-3339 issuance timestamp for reproducible outputs.
        fail_on: Policy gate threshold (``"none"``, ``"under_investigation"``, ``"affected"``).
        policy_affected: Map unexcluded CVEs to ``affected`` instead of ``under_investigation``.
        strict_openvex: Omit root ``meta`` and write ``<output>.meta.json`` sidecar instead.
        report_out: Optional path to archive the intermediate triage report envelope.
    """

    cache_dir: Path
    kernel_version: str
    kernel_config: Path
    output: Path
    profile: str = "auto"
    stable_branch: str | None = None
    mode: str = "full"
    kernel_source: Path | None = None
    kernel_rev: str | None = None
    sec_url: str = DEFAULT_SEC_REPO_URL
    sec_ref: str = DEFAULT_SEC_BRANCH
    skip_refresh: bool = False
    since_year: int | None = None
    cve_ids: list[str] | None = None
    jobs: int = 8
    kmax_formulas: Path | None = None
    experimental_checks: bool = False
    cve_triage_bin: str | None = None
    no_accel: bool = False
    author: str = "KernelVEX Automated Triage"
    role: str = "Automated Kernel CVE Triage Orchestrator"
    doc_id: str | None = None
    kernel_url: str | None = None
    kernel_arch: str | None = None
    product_purl: str | None = None
    timestamp: str | None = None
    fail_on: str = "none"
    policy_affected: bool = False
    strict_openvex: bool = False
    report_out: Path | None = None


def run_ci_pipeline(opts: PipelineOptions) -> tuple[int, dict[str, Any]]:
    """Execute the full CI triage pipeline and return ``(exit_code, summary)``.

    Orchestration stages run in strict provenance order:
    1. Validate execution mode and resolve ``cip`` vs ``standard`` profile + Kconfig SHA-256.
    2. Synchronize ``cip-kernel-sec`` catalog (unless ``skip_refresh=True``).
    3. Run ``analyze quick`` (no sources) or ``analyze full`` (``cve-triage`` + ``.kmax``).
    4. Optionally persist intermediate JSON envelope via atomic replacement.
    5. Convert checks to OpenVEX v0.2.0, validate against JSON Schema, and write outputs.
    6. Evaluate CI gate exit code (``0`` clean, ``10`` open triage, ``30`` policy breach).

    Args:
        opts: Validated ``PipelineOptions`` configuration bundle.

    Returns:
        Tuple ``(exit_code, summary)`` containing the process exit code and audit counts.

    Raises:
        KernelVexError: On invalid options, missing kernel sources in ``full`` mode,
            catalog/triage failure, or schema validation failure (mapped to exit code 20).
    """
    if opts.mode not in ("quick", "full"):
        raise KernelVexError(f"Unsupported --mode {opts.mode!r}; expected 'quick' or 'full'")

    # Enforce compile-time source requirement early before refreshing catalogs unnecessarily.
    if opts.mode == "full" and opts.kernel_source is None:
        raise KernelVexError("--kernel-source is mandatory when --mode full is selected")

    # Resolve target build identity (branch + Kconfig digest) before any network I/O.
    start_ts = time.monotonic()
    profile_cfg = resolve_profile(opts.profile, opts.kernel_version, opts.stable_branch)
    kconfig = load_kconfig(opts.kernel_config)
    kernel_arch = opts.kernel_arch or kconfig.detected_arch

    # Keep catalog synchronization configurable so air-gapped CI jobs can pass --skip-refresh.
    if opts.skip_refresh:
        catalog = load_catalog(opts.cache_dir)
    else:
        catalog = refresh_catalog(
            cache_dir=opts.cache_dir,
            sec_url=opts.sec_url,
            sec_ref=opts.sec_ref,
        )

    # Dispatch strictly between source-free quick mode and compile-time kmax full mode.
    if opts.mode == "quick":
        report_envelope = run_quick_analysis(
            catalog=catalog,
            kconfig=kconfig,
            profile_cfg=profile_cfg,
            since_year=opts.since_year,
            cve_ids=opts.cve_ids,
        )
    else:
        assert opts.kernel_source is not None
        report_envelope = run_full_analysis(
            cache_dir=opts.cache_dir,
            kernel_source=opts.kernel_source,
            kconfig=kconfig,
            profile_cfg=profile_cfg,
            kernel_rev=opts.kernel_rev,
            since_year=opts.since_year,
            cve_ids=opts.cve_ids,
            jobs=opts.jobs,
            kmax_formulas=opts.kmax_formulas,
            experimental_checks=opts.experimental_checks,
            cve_triage_bin=opts.cve_triage_bin,
            no_accel=opts.no_accel,
        )

    # Persist intermediate triage envelope when requested for post-mortem debugging.
    if opts.report_out is not None:
        atomic_write_json(opts.report_out, report_envelope)

    # Assemble and schema-validate the OpenVEX v0.2.0 statement set bound to exact digests.
    vex_doc, audit_meta = emit_openvex(
        report_payload=report_envelope,
        profile_cfg=profile_cfg,
        author=opts.author,
        kernel_arch=kernel_arch,
        config_name=opts.kernel_config.name,
        kernel_config_sha256=kconfig.raw_bytes_sha256,
        sec_commit=catalog["sec_commit"],
        kernel_source_commit=report_envelope["meta"].get("kernel_source_commit"),
        analysis_level=opts.mode,
        kernel_url=opts.kernel_url,
        explicit_purl=opts.product_purl,
        doc_id=opts.doc_id,
        role=opts.role,
        timestamp=opts.timestamp,
        policy_affected=opts.policy_affected,
        strict_openvex=opts.strict_openvex,
    )

    # Write schema-validated OpenVEX output atomically to protect downstream CI artifacts.
    atomic_write_json(opts.output, vex_doc)

    # Emit companion <output>.meta.json sidecar when strict upstream schema bans root meta.
    if opts.strict_openvex:
        # Persist provenance metadata alongside strict OpenVEX documents.
        sidecar = opts.output.with_name(f"{opts.output.name}.meta.json")
        atomic_write_json(sidecar, audit_meta)

    # Compute final exit code (0/10/30) after all artifacts have been safely flushed to disk.
    exit_code, counts = evaluate_policy_exit_code(vex_doc, fail_on=opts.fail_on)
    elapsed_s = round(time.monotonic() - start_ts, 3)

    # Record structured run summary to stderr for CI log aggregation and CRA audit trails.
    summary = {
        "exit_code": exit_code,
        "profile": profile_cfg.profile,
        "stable_branch": profile_cfg.stable_branch,
        "mode": opts.mode,
        "sec_commit": audit_meta["sec_commit"],
        "kernel_source_commit": audit_meta["kernel_source_commit"],
        "statement_count": len(vex_doc["statements"]),
        "status_counts": counts,
        "output": str(opts.output),
        "elapsed_seconds": elapsed_s,
    }
    logger.info("Pipeline completed", extra=summary)
    return (exit_code, summary)
