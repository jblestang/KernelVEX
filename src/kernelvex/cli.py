"""Command-line interface and structured logging entrypoint for ``kernelvex``.

Implements the stable CI/CD subcommand contract without introducing any custom
CVE analysis engine outside upstream OSS composition:
- ``kernelvex catalog refresh``: Sync ``cip-kernel-sec`` and rebuild ``catalog.json``.
- ``kernelvex catalog merge-enrich``: Merge ``affected-files`` / ``affected-configs``.
- ``kernelvex enrich``: Wrap ``cve-triage enrich`` over target kernel revisions.
- ``kernelvex analyze quick``: Fast conservative triage using versions + ``.config``.
- ``kernelvex analyze full``: Compile-time proof via ``cve-triage triage`` + ``kmax``.
- ``kernelvex vex emit``: Convert report JSON into schema-validated OpenVEX v0.2.0.
- ``kernelvex ci pipeline``: End-to-end orchestration with deterministic exit codes
  (``0`` clean, ``10`` open triage, ``20`` tooling/input error, ``30`` policy fail).

All operational telemetry logs are emitted to ``stderr`` (JSON lines by default)
so stdout remains unpolluted if callers redirect paths or pipe summaries.
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from kernelvex import (
    DEFAULT_SEC_BRANCH,
    DEFAULT_SEC_REPO_URL,
    EXIT_OK,
    EXIT_TOOL_ERROR,
    KernelVexError,
    __version__,
)
from kernelvex.catalog import (
    atomic_write_json,
    load_catalog,
    merge_enriched_dir,
    read_sec_commit,
    refresh_catalog,
    resolve_cache_dir,
)
from kernelvex.full import run_enrich_wrapper, run_full_analysis
from kernelvex.kconfig import load_kconfig
from kernelvex.openvex import emit_openvex, evaluate_policy_exit_code
from kernelvex.pipeline import PipelineOptions, run_ci_pipeline
from kernelvex.profile import resolve_profile
from kernelvex.quick import run_quick_analysis

# Extra LogRecord attributes preserved in JSON structured logs.
_STANDARD_LOG_ATTRS = frozenset(logging.LogRecord("", 0, "", 0, "", (), None).__dict__.keys())


class _JsonLogFormatter(logging.Formatter):
    """Emit structured single-line JSON log records to stderr for CI auditability.

    Preserves arbitrary ``extra={...}`` fields (such as ``sec_commit``,
    ``kmax_cache_hit``, and per-status OpenVEX counts) while stripping standard
    Python ``LogRecord`` internals to keep CI log lines compact and machine-parseable.
    """

    def format(self, record: logging.LogRecord) -> str:
        """Serialize one ``logging.LogRecord`` into a single UTC JSON log line.

        Args:
            record: Standard Python logging event possibly carrying ``extra`` context.

        Returns:
            Single-line UTF-8 JSON string containing ISO-8601 timestamp and extras.
        """
        payload: dict[str, Any] = {
            "timestamp": datetime.now(UTC).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        # Merge caller-supplied extra attributes without leaking internal LogRecord fields.
        for key, value in record.__dict__.items():
            if key not in _STANDARD_LOG_ATTRS and not key.startswith("_"):
                payload[key] = value
        return json.dumps(payload, default=str)


def _configure_logging(log_format: str, verbose: int) -> None:
    """Configure root logger on stderr with JSON or human-readable output.

    Replaces existing handlers so repeated in-process invocations from tests do
    not duplicate log lines on stderr.

    Args:
        log_format: ``"json"`` for structured CI logs or ``"text"`` for local terminals.
        verbose: Count of ``-v`` flags; values ``> 0`` enable ``DEBUG`` logging.
    """
    root = logging.getLogger()
    root.handlers.clear()
    # Direct all logs to stderr so output files and stdout remain cleanly separated.
    handler = logging.StreamHandler(sys.stderr)
    if log_format == "json":
        handler.setFormatter(_JsonLogFormatter())
    else:
        handler.setFormatter(logging.Formatter("%(levelname)s %(name)s: %(message)s"))
    root.addHandler(handler)
    root.setLevel(logging.DEBUG if verbose > 0 else logging.INFO)


def _add_shared_runtime_args(parser: argparse.ArgumentParser) -> None:
    """Attach shared cache/logging flags using SUPPRESS so position is flexible.

    Registering ``--cache-dir``, ``--log-format``, and ``-v`` with
    ``argparse.SUPPRESS`` on leaf subparsers lets users place shared flags either
    before the subcommand (``kernelvex --cache-dir ... ci pipeline``) or after
    it (``kernelvex ci pipeline --cache-dir ...``) without overriding top-level values.

    Args:
        parser: Leaf subcommand ``ArgumentParser`` to augment.
    """
    # Override global cache location (e.g. mounted CI volume /cache).
    parser.add_argument(
        "--cache-dir",
        default=argparse.SUPPRESS,
        help="Persistent cache directory (default: $KERNELVEX_CACHE_DIR or .cache/kernelvex)",
    )
    # Switch between CI-parseable JSON lines and terminal text diagnostics.
    parser.add_argument(
        "--log-format",
        choices=("json", "text"),
        default=argparse.SUPPRESS,
        help="Structured log format on stderr (default: json)",
    )
    # Enable DEBUG diagnostics on demand without polluting default JSON logs.
    parser.add_argument(
        "-v",
        "--verbose",
        action="count",
        default=argparse.SUPPRESS,
        help="Increase log verbosity",
    )


def _add_profile_and_kernel_args(parser: argparse.ArgumentParser) -> None:
    """Attach mandatory target build identifiers (version + Kconfig) and profile.

    Every production analysis or VEX emission command requires the effective target
    version and effective ``.config`` (never heuristics from version alone).

    Args:
        parser: Target subcommand parser (``quick``, ``full``, ``emit``, ``pipeline``).
    """
    # Auto-detects CIP when kernel tag has *-cip*/*-st* or branch begins with cip/.
    parser.add_argument(
        "--profile",
        choices=("auto", "cip", "standard"),
        default="auto",
        help="Kernel triage profile: auto-detect (*-cip* -> cip), cip, or standard",
    )
    # Effective built kernel version or git tag (never optional in production).
    parser.add_argument(
        "--kernel-version",
        required=True,
        help="Target kernel version or tag (e.g. v5.10.224-cip52 or 5.15.165)",
    )
    # Effective kernel .config or /proc/config.gz (always hashed with SHA-256).
    parser.add_argument(
        "--kernel-config",
        required=True,
        help="Path to effective .config or /proc/config.gz",
    )
    # Explicit branch key in cip-kernel-sec when vendor trees track custom series.
    parser.add_argument(
        "--stable-branch",
        default=None,
        help="Target branch key in cip-kernel-sec (e.g. cip/5.10 or stable/5.15)",
    )


def _add_cve_filter_args(parser: argparse.ArgumentParser) -> None:
    """Attach deterministic CVE year and ID scoping flags for CI runs.

    Scoping is often used in integration jobs (e.g. ``--cve-since-year 2024``)
    or targeted regression triage without inventing any local synthetic CVE lists.

    Args:
        parser: Target subcommand parser supporting CVE selection filters.
    """
    # Inclusive year cutoff (e.g. 2024 restricts triage to modern CRA window).
    parser.add_argument(
        "--cve-since-year",
        type=int,
        default=None,
        help="Restrict evaluation to CVEs from this year onward (e.g. 2024)",
    )
    # Explicit CVE list from cip-kernel-sec for targeted regression verification.
    parser.add_argument(
        "--cve-id",
        nargs="+",
        default=None,
        help="Evaluate only specific CVE identifiers (e.g. CVE-2024-40901)",
    )


def _add_openvex_args(parser: argparse.ArgumentParser) -> None:
    """Attach OpenVEX document metadata, SBOM PURL linking, and CRA gate options.

    Shared identically across ``vex emit`` and ``ci pipeline`` so offline report
    re-emission and one-shot CI runs expose identical policy and schema controls.

    Args:
        parser: Parser for OpenVEX-producing commands.
    """
    # Author & identity metadata attached to every OpenVEX root document.
    parser.add_argument(
        "--author",
        default="KernelVEX Automated Triage",
        help="OpenVEX author identifier",
    )
    parser.add_argument(
        "--role",
        default="Automated Kernel CVE Triage Orchestrator",
        help="OpenVEX author role",
    )
    # Allow external release engineering systems to supply canonical document URIs.
    parser.add_argument(
        "--id",
        "--doc-id",
        dest="doc_id",
        default=None,
        help="Explicit IRI identifying the OpenVEX document",
    )
    # SBOM PURL & provenance overrides for vendor/distro/Yocto integrations.
    parser.add_argument("--kernel-url", default=None, help="Upstream kernel git URL for PURL")
    parser.add_argument("--kernel-arch", default=None, help="Override inferred kernel architecture")
    # Bind OpenVEX directly to an existing CycloneDX/SPDX kernel component PURL.
    parser.add_argument(
        "--product-purl",
        default=None,
        help="Explicit SBOM component PURL overriding URL-derived PURL",
    )
    # Deterministic timestamps permit reproducible builds across repeated CI reruns.
    parser.add_argument("--timestamp", default=None, help="Override ISO-8601 issuance timestamp")
    # Conservative CRA policy controls: affected opt-in, strict schema sidecar, exit gate.
    # Default emits under_investigation unless product policy explicitly enables --policy-affected.
    parser.add_argument(
        "--policy-affected",
        action="store_true",
        help="Emit 'affected' instead of 'under_investigation' when checks do not exclude a CVE",
    )
    # Strict schema mode omits root `meta` and places provenance into <output>.meta.json.
    parser.add_argument(
        "--strict-openvex",
        action="store_true",
        help="Omit root 'meta' and emit <output>.meta.json sidecar for strict upstream schema",
    )
    # Exit code gate controlling advisory (exit 10) vs blocking (exit 30) CI behavior.
    parser.add_argument(
        "--fail-on",
        choices=("none", "under_investigation", "affected"),
        default="none",
        help="Exit 30 if remaining open CVEs breach policy threshold",
    )


def _register_catalog_parsers(subparsers: argparse._SubParsersAction[Any]) -> None:
    """Register ``catalog refresh`` and ``catalog merge-enrich`` subcommands.

    Separates upstream database synchronization and optional ``cve-triage enrich``
    metadata ingestion from per-build vulnerability evaluation commands.

    Args:
        subparsers: Root CLI subparsers container.
    """
    catalog_parser = subparsers.add_parser("catalog", help="Manage cip-kernel-sec catalog cache")
    catalog_sub = catalog_parser.add_subparsers(dest="catalog_cmd", required=True)

    # `catalog refresh` pulls cip-kernel-sec into cache and rebuilds catalog.json.
    # Supports --sec-url for offline mirrors and --sec-ref for branches, tags, or SHAs.
    refresh_p = catalog_sub.add_parser(
        "refresh", help="Clone/pull cip-kernel-sec and rebuild versioned catalog.json"
    )
    _add_shared_runtime_args(refresh_p)
    # Mirror URL allows air-gapped CI runners to sync from an internal cip-kernel-sec clone.
    refresh_p.add_argument("--sec-url", default=DEFAULT_SEC_REPO_URL, help="cip-kernel-sec git URL")
    refresh_p.add_argument("--sec-ref", default=DEFAULT_SEC_BRANCH, help="Git branch, tag, or SHA")
    # `--force` rebuilds catalog.json even when cached HEAD matches sec_commit in metadata.
    refresh_p.add_argument(
        "--force", action="store_true", help="Force YAML re-parse even if cached"
    )

    # `catalog merge-enrich` overlays cve-triage enrich YAML formulas into catalog.json
    # so subsequent `analyze quick` runs can exclude CVEs with disabled Kconfig symbols.
    merge_p = catalog_sub.add_parser(
        "merge-enrich", help="Merge cve-triage enrich YAML outputs into catalog.json"
    )
    _add_shared_runtime_args(merge_p)
    # Expects a directory containing CVE-*.yml artifacts emitted by `cve-triage enrich`.
    merge_p.add_argument(
        "--enriched-dir", required=True, help="Directory of enriched CVE-*.yml files"
    )


def _register_enrich_parser(subparsers: argparse._SubParsersAction[Any]) -> None:
    """Register the ``enrich`` wrapper subcommand around ``cve-triage enrich``.

    Requires a local kernel git checkout with release history; writes per-CVE
    YAML files without mutating the cached ``cip-kernel-sec`` git mirror.

    Args:
        subparsers: Root CLI subparsers container.
    """
    enrich_p = subparsers.add_parser(
        "enrich", help="Run cve-triage enrich to generate affected-files/affected-configs"
    )
    _add_shared_runtime_args(enrich_p)
    # Kernel source tree and target kernel release branches evaluated by cve-triage enrich.
    enrich_p.add_argument("--kernel-source", required=True, help="Path to local kernel git tree")
    enrich_p.add_argument(
        "--versions", nargs="+", required=True, help="Target branches (e.g. v5.10 v6.12)"
    )
    enrich_p.add_argument("--out-dir", "-o", default="enriched", help="Output enriched directory")
    # Profile defaults to CIP because enrich relies heavily on CIP branch metadata.
    enrich_p.add_argument(
        "--profile", choices=("cip", "standard"), default="cip", help="Target branch family"
    )
    # Optional precomputed kmax cache accelerates repeated enrich runs across releases.
    enrich_p.add_argument("--kmax-formulas", default=None, help="Optional kmax cache path")
    # Explicit executable override facilitates hermetic toolchains and CI smoke testing.
    enrich_p.add_argument("--cve-triage-bin", default=None, help="Override cve-triage executable")
    # Apply year/ID scoping before generating YAML lists for upstream enrich.
    _add_cve_filter_args(enrich_p)


def _register_analyze_parsers(subparsers: argparse._SubParsersAction[Any]) -> None:
    """Register ``analyze quick`` (no sources) and ``analyze full`` (``cve-triage``).

    Args:
        subparsers: Root CLI subparsers container.
    """
    analyze_parser = subparsers.add_parser("analyze", help="Run quick or full kernel CVE triage")
    analyze_sub = analyze_parser.add_subparsers(dest="analyze_cmd", required=True)

    # `analyze quick` skips kernel checkout & kmax; active CONFIG stays under_investigation.
    # Emits analysis_level="quick" and null kernel_source_commit in the output envelope.
    quick_p = analyze_sub.add_parser(
        "quick", help="Conservative triage using version ranges, .config, and catalog (no kmax)"
    )
    _add_shared_runtime_args(quick_p)
    _add_profile_and_kernel_args(quick_p)
    _add_cve_filter_args(quick_p)
    # Accept -o/--out/--output aliases to align with cve-triage CLI conventions.
    quick_p.add_argument(
        "--output", "-o", "--out", dest="output", default="report.quick.json", help="Output JSON"
    )

    # `analyze full` invokes upstream `cve-triage triage` with persistent `.kmax` cache.
    # Accepts plain .config or /proc/config.gz exports and creates an isolated git worktree.
    full_p = analyze_sub.add_parser(
        "full", help="Compile-time proof triage via kernel-cve-triage + kmax"
    )
    _add_shared_runtime_args(full_p)
    _add_profile_and_kernel_args(full_p)
    # Kernel git checkout options and explicit revision override when uname -r != git tag.
    full_p.add_argument("--kernel-source", required=True, help="Local kernel git tree path")
    full_p.add_argument("--kernel-rev", default=None, help="Git tag or commit if != kernel-version")
    # Concurrency, kmax formula cache file override, and optional line-level Kmax checks.
    full_p.add_argument("--jobs", "-j", type=int, default=8, help="Parallel triage workers")
    # Passing a pre-seeded .kmax file shares formulas across different CI runner workspaces.
    full_p.add_argument("--kmax-formulas", default=None, help="Persistent .kmax cache file path")
    full_p.add_argument(
        "--experimental-checks", action="store_true", help="Enable line-level experimental checks"
    )
    full_p.add_argument("--cve-triage-bin", default=None, help="Override cve-triage executable")
    full_p.add_argument(
        "--no-accel",
        action="store_true",
        help="Disable in-process kernelvex.accel optimization hooks",
    )
    # Optional raw JSON dump preserves exact unmodified cve-triage array output for audits.
    full_p.add_argument(
        "--raw-report-out", default=None, help="Optional path for raw cve-triage array JSON"
    )
    _add_cve_filter_args(full_p)
    # Enveloped output carries CRA build metadata alongside raw upstream check results.
    full_p.add_argument(
        "--output", "-o", "--out", dest="output", default="report.full.json", help="Output JSON"
    )


def _register_vex_parser(subparsers: argparse._SubParsersAction[Any]) -> None:
    """Register ``vex emit`` to convert triage reports into OpenVEX v0.2.0 documents.

    Supports both ``kernelvex`` envelopes (``{meta, reports}``) and raw arrays
    exported directly by upstream ``cve-triage triage --out``.

    Args:
        subparsers: Root CLI subparsers container.
    """
    vex_parser = subparsers.add_parser("vex", help="Emit and validate OpenVEX 0.2.0 documents")
    vex_sub = vex_parser.add_subparsers(dest="vex_cmd", required=True)

    # Converts a previously generated report JSON into schema-validated OpenVEX 0.2.0.
    emit_p = vex_sub.add_parser("emit", help="Convert quick/full triage report to OpenVEX 0.2.0")
    _add_shared_runtime_args(emit_p)
    _add_profile_and_kernel_args(emit_p)
    _add_openvex_args(emit_p)
    # Input JSON can be generated either by kernelvex analyze or directly by cve-triage.
    emit_p.add_argument("--report", required=True, help="Path to quick/full or raw report JSON")
    # Provenance overrides needed primarily when ingesting raw cve-triage array JSONs
    # that lack kernelvex's outer `meta` envelope header.
    emit_p.add_argument(
        "--analysis-level",
        choices=("quick", "full"),
        default="full",
        help="Analysis level when input is a raw cve-triage JSON array",
    )
    # Optional 40-char SHA overrides complete audit metadata when emitting from raw arrays.
    emit_p.add_argument("--sec-commit", default=None, help="Override 40-char cip-kernel-sec SHA")
    emit_p.add_argument(
        "--kernel-source-commit", default=None, help="Optional 40-char kernel git commit SHA"
    )
    # Emits strict OpenVEX 0.2.0 JSON (with embedded meta or sidecar metadata JSON).
    emit_p.add_argument(
        "--output", "-o", "--out", dest="output", default="openvex.json", help="Output OpenVEX JSON"
    )


def _register_ci_parser(subparsers: argparse._SubParsersAction[Any]) -> None:
    """Register ``ci pipeline`` one-shot CI/CD entrypoint with policy exit codes.

    Designed as container ``ENTRYPOINT`` target chaining ``refresh -> analyze -> vex``
    and returning deterministic ``0``, ``10``, ``20``, or ``30`` status codes.

    Args:
        subparsers: Root CLI subparsers container.
    """
    ci_parser = subparsers.add_parser("ci", help="One-shot CI/CD integration commands")
    ci_sub = ci_parser.add_subparsers(dest="ci_cmd", required=True)

    # Executes end-to-end CI triage with configurable mode (quick/full) and policy gate.
    pipe_p = ci_sub.add_parser(
        "pipeline",
        help="Refresh catalog, run quick/full triage, emit OpenVEX, and enforce exit code",
    )
    _add_shared_runtime_args(pipe_p)
    _add_profile_and_kernel_args(pipe_p)
    _add_cve_filter_args(pipe_p)
    _add_openvex_args(pipe_p)
    # Execution mode switch: `full` requires --kernel-source; `quick` omits kernel git tree.
    pipe_p.add_argument(
        "--mode", choices=("quick", "full"), default="full", help="Execution mode (default: full)"
    )
    # Local git checkout is mandatory when --mode full is selected in CI pipelines.
    pipe_p.add_argument(
        "--kernel-source", default=None, help="Kernel git checkout path (required for --mode full)"
    )
    pipe_p.add_argument("--kernel-rev", default=None, help="Explicit git revision if != version")
    # Catalog sync options allow pinned mirrors (--sec-ref <sha>) or offline cached runs.
    pipe_p.add_argument("--sec-url", default=DEFAULT_SEC_REPO_URL, help="cip-kernel-sec git URL")
    pipe_p.add_argument("--sec-ref", default=DEFAULT_SEC_BRANCH, help="cip-kernel-sec git ref")
    # `--skip-refresh` lets air-gapped or pre-warmed CI jobs reuse /cache/catalog.json.
    pipe_p.add_argument(
        "--skip-refresh",
        action="store_true",
        help="Use existing cached catalog.json without fetching remote cip-kernel-sec",
    )
    # Full-mode backend controls: parallelism, kmax cache file, experimental checks, binary.
    pipe_p.add_argument("--jobs", "-j", type=int, default=8, help="Parallel cve-triage jobs")
    pipe_p.add_argument("--kmax-formulas", default=None, help="Persistent .kmax cache file path")
    # Line-level experimental checks remain opt-in to match upstream cve-triage defaults.
    pipe_p.add_argument(
        "--experimental-checks", action="store_true", help="Enable experimental line checks"
    )
    pipe_p.add_argument("--cve-triage-bin", default=None, help="Override cve-triage executable")
    pipe_p.add_argument(
        "--no-accel",
        action="store_true",
        help="Disable in-process kernelvex.accel optimization hooks",
    )
    # Optional archive of intermediate report JSON alongside primary OpenVEX artifact.
    pipe_p.add_argument("--report-out", default=None, help="Optional path to save triage report")
    # Primary compliance artifact consumed by SBOM/VEX release gates and attestation steps.
    pipe_p.add_argument(
        "--output", "-o", "--out", dest="output", default="openvex.json", help="Output OpenVEX JSON"
    )


def _build_parser() -> argparse.ArgumentParser:
    """Construct the complete ``kernelvex`` CLI argument parser hierarchy.

    Defines five top-level command namespaces:
    ``catalog`` (``refresh``, ``merge-enrich``), ``enrich``,
    ``analyze`` (``quick``, ``full``), ``vex emit``, and ``ci pipeline``.

    Returns:
        Configured ``argparse.ArgumentParser`` instance ready for ``parse_args``.
    """
    parser = argparse.ArgumentParser(
        prog="kernelvex",
        description=(
            "Industrial Linux kernel CVE triage & OpenVEX 0.2.0 orchestrator "
            "(cip-kernel-sec + kernel-cve-triage + kmax)"
        ),
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    # Register root defaults here so leaf SUPPRESS flags never clobber top-level values.
    parser.add_argument(
        "--cache-dir",
        default=None,
        help="Persistent cache directory (default: $KERNELVEX_CACHE_DIR or .cache/kernelvex)",
    )
    parser.add_argument(
        "--log-format",
        choices=("json", "text"),
        default="json",
        help="Structured log format on stderr (default: json)",
    )
    parser.add_argument("-v", "--verbose", action="count", default=0, help="Increase log verbosity")

    # Top-level namespace mirrors the 5 pipeline stages documented in the CLI contract.
    subparsers = parser.add_subparsers(dest="command", required=True)
    _register_catalog_parsers(subparsers)
    _register_enrich_parser(subparsers)
    _register_analyze_parsers(subparsers)
    _register_vex_parser(subparsers)
    _register_ci_parser(subparsers)
    return parser


def _handle_catalog(args: argparse.Namespace, cache_dir: Path, logger: logging.Logger) -> int:
    """Dispatch ``catalog refresh`` and ``catalog merge-enrich`` subcommands.

    Args:
        args: Parsed CLI namespace for ``catalog`` commands.
        cache_dir: Persistent cache root path.
        logger: Structured module logger.

    Returns:
        ``EXIT_OK`` (``0``) on completion.
    """
    # Branch between pulling upstream cip-kernel-sec YAML vs merging local enrich output.
    if args.catalog_cmd == "refresh":
        catalog = refresh_catalog(
            cache_dir=cache_dir,
            sec_url=args.sec_url,
            sec_ref=args.sec_ref,
            force=args.force,
        )
        logger.info(
            "Catalog refreshed",
            extra={"sec_commit": catalog["sec_commit"], "cve_count": catalog["cve_count"]},
        )
        return EXIT_OK

    # Only remaining validated catalog_cmd is "merge-enrich".
    catalog = merge_enriched_dir(cache_dir=cache_dir, enriched_dir=Path(args.enriched_dir))
    logger.info(
        "Merged enrichment metadata",
        extra={
            "sec_commit": catalog["sec_commit"],
            "merged_files": catalog.get("enriched_merged_count", 0),
        },
    )
    return EXIT_OK


def _handle_analyze(args: argparse.Namespace, cache_dir: Path, logger: logging.Logger) -> int:
    """Dispatch ``analyze quick`` and ``analyze full`` subcommands atomically.

    Args:
        args: Parsed CLI namespace for ``analyze`` commands.
        cache_dir: Persistent cache root path.
        logger: Structured module logger.

    Returns:
        ``EXIT_OK`` (``0``) after writing the triage report envelope.
    """
    # Resolve CIP vs standard profile and parse effective .config/.config.gz upfront
    # so invalid versions or unreadable configs abort immediately before subprocesses start.
    profile_cfg = resolve_profile(args.profile, args.kernel_version, args.stable_branch)
    kconfig = load_kconfig(Path(args.kernel_config))

    if args.analyze_cmd == "quick":
        # Quick mode relies strictly on cached catalog.json + .config without kernel sources.
        catalog = load_catalog(cache_dir)
        envelope = run_quick_analysis(
            catalog=catalog,
            kconfig=kconfig,
            profile_cfg=profile_cfg,
            since_year=args.cve_since_year,
            cve_ids=args.cve_id,
        )
        # Write via temp file + atomic rename so concurrent readers never see half-written JSON.
        out_path = Path(args.output)
        atomic_write_json(out_path, envelope)
        logger.info(
            "Quick analysis completed",
            extra={"output": str(out_path), "report_count": len(envelope["reports"])},
        )
        return EXIT_OK

    # `analyze full` delegates compile-time proof to upstream `cve-triage triage`.
    envelope = run_full_analysis(
        cache_dir=cache_dir,
        kernel_source=Path(args.kernel_source),
        kconfig=kconfig,
        profile_cfg=profile_cfg,
        kernel_rev=args.kernel_rev,
        since_year=args.cve_since_year,
        cve_ids=args.cve_id,
        jobs=args.jobs,
        kmax_formulas=Path(args.kmax_formulas) if args.kmax_formulas else None,
        experimental_checks=args.experimental_checks,
        cve_triage_bin=args.cve_triage_bin,
        raw_report_out=Path(args.raw_report_out) if args.raw_report_out else None,
        no_accel=args.no_accel,
    )
    out_path = Path(args.output)
    atomic_write_json(out_path, envelope)
    logger.info(
        "Full analysis completed",
        extra={
            "output": str(out_path),
            "report_count": len(envelope["reports"]),
            "kmax_cache_hit": envelope["meta"]["kmax_cache_hit"],
        },
    )
    return EXIT_OK


def _handle_vex_emit(args: argparse.Namespace, cache_dir: Path, logger: logging.Logger) -> int:
    """Dispatch ``vex emit`` to validate and serialize OpenVEX v0.2.0 documents.

    Args:
        args: Parsed CLI namespace for ``vex emit``.
        cache_dir: Persistent cache root path for ``sec_commit`` fallback lookup.
        logger: Structured module logger.

    Returns:
        Policy-evaluated exit code (``0``, ``10``, or ``30``).

    Raises:
        KernelVexError: If the input report JSON is missing, unreadable, or malformed.
    """
    # Resolve target profile and compute SHA-256 of the effective kernel .config.
    profile_cfg = resolve_profile(args.profile, args.kernel_version, args.stable_branch)
    kconfig = load_kconfig(Path(args.kernel_config))
    report_path = Path(args.report)
    if not report_path.is_file():
        raise KernelVexError(f"Report file does not exist: {report_path}")
    try:
        # Accepts either a kernelvex {meta, reports} envelope or raw cve-triage JSON array.
        payload = json.loads(report_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise KernelVexError(f"Failed to parse report JSON {report_path}: {exc}") from exc

    # Fall back to cached sec_commit when converting raw cve-triage JSON lists.
    resolved_sec = args.sec_commit or read_sec_commit(cache_dir) or ""
    vex_doc, audit_meta = emit_openvex(
        report_payload=payload,
        profile_cfg=profile_cfg,
        author=args.author,
        kernel_arch=args.kernel_arch or kconfig.detected_arch,
        config_name=Path(args.kernel_config).name,
        kernel_config_sha256=kconfig.raw_bytes_sha256,
        sec_commit=resolved_sec,
        kernel_source_commit=args.kernel_source_commit,
        analysis_level=args.analysis_level,
        kernel_url=args.kernel_url,
        explicit_purl=args.product_purl,
        doc_id=args.doc_id,
        role=args.role,
        timestamp=args.timestamp,
        policy_affected=args.policy_affected,
        strict_openvex=args.strict_openvex,
    )
    # Persist schema-validated OpenVEX atomically before evaluating the CI policy gate.
    out_path = Path(args.output)
    atomic_write_json(out_path, vex_doc)
    # Strict upstream mode writes provenance metadata beside the primary OpenVEX artifact.
    if args.strict_openvex:
        sidecar = out_path.with_name(f"{out_path.name}.meta.json")
        atomic_write_json(sidecar, audit_meta)
    # Exit code distinguishes 0 (clean), 10 (open triage), and 30 (--fail-on violation).
    exit_code, counts = evaluate_policy_exit_code(vex_doc, fail_on=args.fail_on)
    logger.info("OpenVEX document emitted", extra={"output": str(out_path), **counts})
    return exit_code


def _handle_enrich(args: argparse.Namespace, cache_dir: Path, logger: logging.Logger) -> int:
    """Dispatch ``kernelvex enrich`` to generate enriched Kconfig YAML files.

    Delegates completely to upstream ``cve-triage enrich`` without implementing
    any custom Kbuild extractor; logs destination path cleanly to stderr.

    Args:
        args: Parsed CLI namespace for ``enrich``.
        cache_dir: Persistent cache root containing ``cip-kernel-sec``.
        logger: Structured module logger.

    Returns:
        ``EXIT_OK`` (``0``) when enrichment completes cleanly.
    """
    out_dir = run_enrich_wrapper(
        cache_dir=cache_dir,
        kernel_source=Path(args.kernel_source),
        versions=args.versions,
        out_dir=Path(args.out_dir),
        cip=(args.profile == "cip"),
        since_year=args.cve_since_year,
        cve_ids=args.cve_id,
        kmax_formulas=Path(args.kmax_formulas) if args.kmax_formulas else None,
        cve_triage_bin=args.cve_triage_bin,
    )
    logger.info("Enrichment completed", extra={"out_dir": str(out_dir)})
    return EXIT_OK


def _handle_ci_pipeline(args: argparse.Namespace, cache_dir: Path) -> int:
    """Dispatch ``kernelvex ci pipeline`` using validated immutable ``PipelineOptions``.

    Chains catalog sync, triage analysis (``quick`` or ``full``), OpenVEX v0.2.0
    emission + Draft 2020-12 schema validation, and policy exit evaluation.

    Args:
        args: Parsed CLI namespace for ``ci pipeline``.
        cache_dir: Persistent cache root path.

    Returns:
        Deterministic CI exit code (``0``, ``10``, or ``30``).
    """
    # Package flat CLI namespace into immutable PipelineOptions for orchestration.
    opts = PipelineOptions(
        cache_dir=cache_dir,
        kernel_version=args.kernel_version,
        kernel_config=Path(args.kernel_config),
        output=Path(args.output),
        profile=args.profile,
        stable_branch=args.stable_branch,
        mode=args.mode,
        kernel_source=Path(args.kernel_source) if args.kernel_source else None,
        kernel_rev=args.kernel_rev,
        sec_url=args.sec_url,
        sec_ref=args.sec_ref,
        skip_refresh=args.skip_refresh,
        since_year=args.cve_since_year,
        cve_ids=args.cve_id,
        jobs=args.jobs,
        kmax_formulas=Path(args.kmax_formulas) if args.kmax_formulas else None,
        experimental_checks=args.experimental_checks,
        cve_triage_bin=args.cve_triage_bin,
        no_accel=args.no_accel,
        author=args.author,
        role=args.role,
        doc_id=args.doc_id,
        kernel_url=args.kernel_url,
        kernel_arch=args.kernel_arch,
        product_purl=args.product_purl,
        timestamp=args.timestamp,
        # Policy flags control conservative status emission and schema strictness.
        fail_on=args.fail_on,
        policy_affected=args.policy_affected,
        strict_openvex=args.strict_openvex,
        report_out=Path(args.report_out) if args.report_out else None,
    )
    # Delegate end-to-end execution + policy gate evaluation to run_ci_pipeline().
    exit_code, _ = run_ci_pipeline(opts)
    return exit_code


def _dispatch(args: argparse.Namespace, cache_dir: Path) -> int:
    """Route the parsed subcommand to its dedicated handler and return exit code.

    All JSON outputs emitted by handlers use atomic temp-file replacement so
    interrupted pipelines never produce partial files.

    Args:
        args: Parsed namespace returned by ``_build_parser()``.
        cache_dir: Resolved persistent cache directory path.

    Returns:
        Deterministic CI exit code (``0``, ``10``, or ``30``); operational failures
        raise ``KernelVexError`` caught by ``main()`` to emit ``20``.

    Raises:
        KernelVexError: On unsupported command combinations or handler failures.
    """
    logger = logging.getLogger("kernelvex.cli")

    # Dispatch table keeps subcommand routing shallow and single-purpose.
    # Each handler returns an explicit POSIX status code rather than mutating globals.
    if args.command == "catalog":
        return _handle_catalog(args, cache_dir, logger)
    if args.command == "enrich":
        return _handle_enrich(args, cache_dir, logger)
    if args.command == "analyze":
        return _handle_analyze(args, cache_dir, logger)
    if args.command == "vex" and args.vex_cmd == "emit":
        return _handle_vex_emit(args, cache_dir, logger)
    if args.command == "ci" and args.ci_cmd == "pipeline":
        return _handle_ci_pipeline(args, cache_dir)

    # Defensive guard in case argparse subcommand validation is bypassed programmatically.
    raise KernelVexError("Unsupported subcommand invocation")


def main(argv: list[str] | None = None) -> int:
    """CLI entrypoint mapping domain errors to exit code 20 and policy to 0/10/30.

    Accepting an optional ``argv`` list keeps the CLI directly testable in-process
    while preserving standard ``sys.argv[1:]`` behavior when invoked as a console script.

    Args:
        argv: Optional argument vector replacing ``sys.argv[1:]``.

    Returns:
        Deterministic process exit code (``0``, ``10``, ``20``, or ``30``).
    """
    parser = _build_parser()
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        # Map argparse usage errors (default exit 2) to deterministic tool error 20
        # while allowing --help / --version (exit 0) to succeed cleanly.
        code = exc.code if isinstance(exc.code, int) else EXIT_TOOL_ERROR
        return EXIT_OK if code == 0 else EXIT_TOOL_ERROR

    # Initialize JSON/text structured logging to stderr and create cache directory tree.
    _configure_logging(args.log_format, args.verbose)
    cache_dir = resolve_cache_dir(args.cache_dir)

    # Trap domain/subprocess failures cleanly so CI receives exit 20 instead of a traceback.
    try:
        return _dispatch(args, cache_dir)
    except KernelVexError as exc:
        logging.getLogger("kernelvex.cli").error(str(exc))
        return EXIT_TOOL_ERROR


# Standard script entrypoint when invoked via `python -m kernelvex.cli`.
if __name__ == "__main__":
    sys.exit(main())
