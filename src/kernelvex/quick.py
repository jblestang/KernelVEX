"""Fast conservative CVE triage using version ranges, ``.config``, and catalog data.

``analyze quick`` never invokes ``kmax`` and never clones kernel sources. It
emits ``not_affected`` or ``fixed`` only when proven by ``cip-kernel-sec``
branch metadata (or enriched ``affected-configs`` expressions); active or
unverified CVEs remain ``under_investigation``.

Trust model and short-circuit order (matching ``kernel-cve-triage``):
1. ``check_ignore``: Excluded if ``ignore.all``, ``ignore.<branch>``, or (under
   ``standard`` profile) ``ignore.mainline`` marks the issue non-applicable.
2. ``check_introduced_by``: Excluded only when ``never`` or strictly newer
   ``introduced-version`` proves vulnerable code is absent from the target tree.
3. ``check_fixed_by``: Cleared as ``fixed`` only when every recorded fix tag on
   the active branch precedes or equals the target kernel version.
4. ``check_kconfig_quick``: Clears as ``not_affected`` only when merged
   ``cve-triage enrich`` formulas exist and all evaluate ``False`` on ``.config``.

Any missing enrichment, unparseable expression, or enabled ``CONFIG_*`` symbol
keeps the CVE conservatively in ``"relevant"`` (``under_investigation``).
"""

from __future__ import annotations

from typing import Any

from kernelvex import PINNED_KERNEL_CVE_TRIAGE_COMMIT, PINNED_KMAX_VERSION
from kernelvex.catalog import select_cves
from kernelvex.kconfig import LoadedKconfig, eval_kmax_config_expr
from kernelvex.profile import ProfileConfig
from kernelvex.versions import ParsedKernelVersion, try_parse_kernel_version

# Report status tokens mirroring upstream cve_triage.triage.checks.CheckResult.
RESULT_NOT_RELEVANT = "not relevant"
RESULT_RELEVANT = "relevant"


def _check_ignore_quick(rec: dict[str, Any], profile_cfg: ProfileConfig) -> dict[str, str]:
    """Evaluate ``cip-kernel-sec`` ignore metadata for the active target branch.

    ``cip-kernel-sec`` records non-issues (e.g. feature backport never applied,
    or architecture/driver irrelevant upstream) under ``ignore.<branch>`` or
    ``ignore.all``. Matching ``ignore.mainline`` additionally applies under the
    ``standard`` profile when the upstream kernel itself rejects the advisory.

    Args:
        rec: Normalized CVE catalog dictionary.
        profile_cfg: Active CIP/standard target profile configuration.

    Returns:
        Check result dictionary compatible with ``cve-triage`` report entries.
    """
    ignore_map = rec.get("ignore") or {}
    if not isinstance(ignore_map, dict) or not ignore_map:
        return {"name": "check_ignore", "result": RESULT_RELEVANT, "reason": "no ignore"}

    # Global upstream ignores apply across all mainline, stable, and CIP series.
    if "all" in ignore_map:
        return {
            "name": "check_ignore",
            "result": RESULT_NOT_RELEVANT,
            "reason": f"ignored: all ({ignore_map['all']})",
        }

    branch = profile_cfg.stable_branch
    if branch in ignore_map:
        return {
            "name": "check_ignore",
            "result": RESULT_NOT_RELEVANT,
            "reason": f"ignored: {branch} ({ignore_map[branch]})",
        }

    # For standard upstream/distro trees, an upstream mainline ignore also clears stable branches.
    if profile_cfg.profile == "standard" and "mainline" in ignore_map:
        return {
            "name": "check_ignore",
            "result": RESULT_NOT_RELEVANT,
            "reason": f"ignored: mainline ({ignore_map['mainline']})",
        }

    return {"name": "check_ignore", "result": RESULT_RELEVANT, "reason": "no matching ignore"}


def _parse_version_list(raw: Any) -> list[ParsedKernelVersion] | None:
    """Parse a non-empty YAML list of version tags monotonically.

    Fails closed by returning ``None`` if any entry in ``raw`` cannot be parsed
    cleanly (e.g. non-version distro strings), ensuring ``analyze quick`` never
    excludes a CVE on partial or ambiguous version metadata.

    Args:
        raw: Candidate list object from ``introduced-version`` or ``fixed-version``.

    Returns:
        Parsed version list when all items parse cleanly, else ``None``.
    """
    if not isinstance(raw, list) or not raw:
        return None
    parsed: list[ParsedKernelVersion] = []
    for item in raw:
        ver = try_parse_kernel_version(str(item))
        if ver is None:
            return None
        parsed.append(ver)
    return parsed


def _check_introduced_quick(rec: dict[str, Any], profile_cfg: ProfileConfig) -> dict[str, str]:
    """Conservatively check whether the CVE was introduced after the target build.

    Excludes a CVE only when ``cip-kernel-sec`` proves absence via explicit
    ``"never"`` markers or strictly newer ``introduced-version`` tags on the target
    branch (or mainline when no branch-specific backport metadata exists).

    Args:
        rec: Normalized CVE catalog dictionary.
        profile_cfg: Resolved profile and parsed target kernel version.

    Returns:
        Check result dict mapped to ``not_affected`` if ``"not relevant"``.
    """
    branch = profile_cfg.stable_branch
    kv = profile_cfg.parsed_version
    intro_by = rec.get("introduced_by") or {}
    intro_ver = rec.get("introduced_version") or {}
    fixed_by = rec.get("fixed_by") or {}
    fixed_ver = rec.get("fixed_version") or {}

    # Verify both explicit commit/version "never" markers across cip-kernel-sec maps.
    if intro_by.get(branch) == "never" or intro_ver.get(branch) == "never":
        return {
            "name": "check_introduced_by",
            "result": RESULT_NOT_RELEVANT,
            "reason": f"introduced-by[{branch}] is never",
        }

    # Fall back to mainline "never" only when the target branch has no branch-local history.
    branch_tracked = (
        branch in intro_by or branch in intro_ver or branch in fixed_by or branch in fixed_ver
    )
    if not branch_tracked and (
        intro_by.get("mainline") == "never" or intro_ver.get("mainline") == "never"
    ):
        return {
            "name": "check_introduced_by",
            "result": RESULT_NOT_RELEVANT,
            "reason": "introduced-by[mainline] is never and branch is unaffected",
        }

    # Every recorded branch introduction tag must postdate our build to exclude safely.
    branch_versions = _parse_version_list(intro_ver.get(branch))
    if branch_versions is not None and all(ver > kv for ver in branch_versions):
        return {
            "name": "check_introduced_by",
            "result": RESULT_NOT_RELEVANT,
            "reason": f"introduced-version[{branch}] {intro_ver[branch]} > {kv.raw}",
        }

    # Mainline-only introductions in newer major.minor series cannot affect older series.
    # Within the same series, require strict ordering (ver > kv) so -rc vs .0 works safely.
    mainline_versions = _parse_version_list(intro_ver.get("mainline"))
    if (
        not branch_tracked
        and mainline_versions is not None
        and all(
            ver.series > kv.series or (ver.series == kv.series and ver > kv)
            for ver in mainline_versions
        )
    ):
        return {
            "name": "check_introduced_by",
            "result": RESULT_NOT_RELEVANT,
            "reason": (f"introduced-version[mainline] {intro_ver['mainline']} postdates {kv.raw}"),
        }

    # When git history is unavailable (quick mode), retain unknown ranges conservatively.
    return {
        "name": "check_introduced_by",
        "result": RESULT_RELEVANT,
        "reason": "introduced version range includes target or is unverified without git history",
    }


def _check_fixed_quick(rec: dict[str, Any], profile_cfg: ProfileConfig) -> dict[str, str]:
    """Conservatively check whether ``fixed-version`` guarantees the fix is present.

    Respects explicit ``"never"`` unfixed markers (e.g. EOL or deferred backports)
    and handles CIP SLTS branches strictly: a CIP build does NOT automatically inherit
    mainline fixes from the same major.minor series unless the CIP tag matches.

    Args:
        rec: Normalized CVE catalog dictionary.
        profile_cfg: Resolved profile and parsed target kernel version.

    Returns:
        Check result dict mapped to ``fixed`` when ``"not relevant"``.
    """
    branch = profile_cfg.stable_branch
    kv = profile_cfg.parsed_version
    fixed_ver = rec.get("fixed_version") or {}
    intro_by = rec.get("introduced_by") or {}
    intro_ver = rec.get("introduced_version") or {}

    # Upstream uses "never" when maintainers decided not to backport the fix to this branch.
    if fixed_ver.get(branch) == "never":
        return {
            "name": "check_fixed_by",
            "result": RESULT_RELEVANT,
            "reason": f"fixed-version[{branch}] is never",
        }

    # Multi-commit fixes require every recorded branch fix tag to be <= target version.
    branch_fixed = _parse_version_list(fixed_ver.get(branch))
    if branch_fixed is not None and all(ver <= kv for ver in branch_fixed):
        return {
            "name": "check_fixed_by",
            "result": RESULT_NOT_RELEVANT,
            "reason": f"fixed-version[{branch}] {fixed_ver[branch]} <= {kv.raw}",
        }

    # Standard LTS/mainline trees inherit mainline fixes within the same or newer series
    # provided the tree does not carry its own branch-specific backport status; CIP SLTS
    # trees require explicit cip/X.Y tracking and never infer fixes from same-series mainline.
    branch_unfixed = branch in intro_by or branch in intro_ver or branch in fixed_ver
    mainline_fixed = _parse_version_list(fixed_ver.get("mainline"))
    if (
        not branch_unfixed
        and mainline_fixed is not None
        and all(
            ver.series < kv.series
            or (profile_cfg.profile == "standard" and ver.series == kv.series and ver <= kv)
            for ver in mainline_fixed
        )
    ):
        return {
            "name": "check_fixed_by",
            "result": RESULT_NOT_RELEVANT,
            "reason": f"fixed-version[mainline] {fixed_ver['mainline']} precedes {kv.raw}",
        }

    # Neither branch nor inherited mainline fix metadata clears this build revision.
    return {
        "name": "check_fixed_by",
        "result": RESULT_RELEVANT,
        "reason": f"fixed-version for {branch} not met by {kv.raw}",
    }


def _select_enriched_configs(
    affected_configs: dict[str, Any], profile_cfg: ProfileConfig
) -> tuple[str | None, list[str]]:
    """Select the closest ``affected-configs`` key matching target kernel version/series.

    Resolution order:
    1. Exact raw version string, ``v``-prefixed tag, or ``stable_branch`` key.
    2. First sorted revision key parsed to the same ``(major, minor)`` kernel series,
       because Kbuild subsystem config dependencies remain stable across minor updates
       within a single SLTS/stable series.

    Args:
        affected_configs: Per-revision Kconfig boolean formula map from ``catalog.json``.
        profile_cfg: Resolved target profile and parsed kernel version.

    Returns:
        Tuple ``(matched_revision_key, formulas_list)``, or ``(None, [])`` if absent.
    """
    if not isinstance(affected_configs, dict) or not affected_configs:
        return (None, [])

    kv = profile_cfg.parsed_version
    # Prefer exact raw/tag/branch match before falling back to same major.minor series.
    for candidate_key in (kv.raw, f"v{kv.raw.lstrip('v')}", profile_cfg.stable_branch):
        exprs = affected_configs.get(candidate_key)
        if isinstance(exprs, list) and exprs:
            return (candidate_key, [str(e) for e in exprs])

    # Sort keys deterministically so repeated quick evaluations yield stable audit notes.
    # Match only when series (major, minor) aligns so 6.x formulas never misapply to 5.10.
    for rev_key in sorted(affected_configs.keys()):
        parsed_rev = try_parse_kernel_version(str(rev_key))
        if parsed_rev is not None and parsed_rev.series == kv.series:
            exprs = affected_configs[rev_key]
            if isinstance(exprs, list) and exprs:
                return (str(rev_key), [str(e) for e in exprs])

    return (None, [])


def _check_kconfig_quick(
    rec: dict[str, Any], kconfig: LoadedKconfig, profile_cfg: ProfileConfig
) -> dict[str, str]:
    """Evaluate enriched Kconfig formulas conservatively without invoking ``kmax``.

    In ``quick`` mode:
    - Disabled formulas (every expression evaluates ``False``) prove the vulnerable
      subsystem is not built -> ``"not relevant"`` (``not_affected``).
    - Enabled formulas, missing enrichment, or unparseable formulas remain
      ``"relevant"`` (``under_investigation``), because ``quick`` lacks exact
      Kbuild/line proof.

    Args:
        rec: Normalized CVE catalog record (possibly merged with ``cve-triage enrich``).
        kconfig: Parsed effective kernel ``.config``.
        profile_cfg: Active target profile and kernel version.

    Returns:
        Check result dictionary for ``check_kconfig_quick``.
    """
    matched_rev, exprs = _select_enriched_configs(rec.get("affected_configs") or {}, profile_cfg)
    if matched_rev is None or not exprs:
        # Unenriched CVEs stay under_investigation because quick mode has no source tree.
        return {
            "name": "check_kconfig_quick",
            "result": RESULT_RELEVANT,
            "reason": "no enriched kmax config formula; conservative quick triage",
        }

    active_exprs: list[str] = []
    for expr in exprs:
        try:
            is_enabled = eval_kmax_config_expr(expr, kconfig.enabled_options)
        except ValueError as exc:
            # Never emit not_affected if a boolean formula cannot be parsed cleanly.
            return {
                "name": "check_kconfig_quick",
                "result": RESULT_RELEVANT,
                "reason": f"unparseable kconfig formula ({exc}); conservative quick triage",
            }
        if is_enabled:
            active_exprs.append(expr)

    if active_exprs:
        return {
            "name": "check_kconfig_quick",
            "result": RESULT_RELEVANT,
            "reason": f"active Kconfig constraint [{matched_rev}]: {'; '.join(active_exprs)}",
        }

    return {
        "name": "check_kconfig_quick",
        "result": RESULT_NOT_RELEVANT,
        "reason": f"disabled Kconfig constraint [{matched_rev}]: {'; '.join(exprs)}",
    }


def run_quick_analysis(
    catalog: dict[str, Any],
    kconfig: LoadedKconfig,
    profile_cfg: ProfileConfig,
    since_year: int | None = None,
    cve_ids: list[str] | None = None,
) -> dict[str, Any]:
    """Run ``analyze quick`` across selected catalog CVEs without kernel sources.

    Mirrors ``kernel-cve-triage``'s sequential short-circuit check pipeline while
    avoiding any git checkout or ``kmax`` build execution. Records
    ``analysis_level="quick"`` and ``kernel_source_commit=None`` in the envelope
    metadata for CRA auditability.

    Args:
        catalog: Loaded ``catalog.json`` dictionary from ``cip-kernel-sec``.
        kconfig: Parsed effective kernel ``.config``.
        profile_cfg: Resolved ``cip`` or ``standard`` target profile.
        since_year: Optional inclusive lower bound on CVE year.
        cve_ids: Optional explicit list of CVE identifiers.

    Returns:
        ``kernelvex`` report envelope dictionary ready for ``vex emit``.

    Raises:
        KernelVexError: If requested CVEs are missing or none match the profile.
    """
    selected = select_cves(
        catalog,
        profile=profile_cfg.profile,
        since_year=since_year,
        cve_ids=cve_ids,
    )

    reports: list[dict[str, Any]] = []
    for rec in selected:
        check_results: list[dict[str, str]] = []
        # Follow cve-triage short-circuit order: ignore -> introduced -> fixed -> kconfig.
        # Once any check emits "not relevant", later checks are unnecessary and skipped.
        for check_fn in (
            lambda r: _check_ignore_quick(r, profile_cfg),
            lambda r: _check_introduced_quick(r, profile_cfg),
            lambda r: _check_fixed_quick(r, profile_cfg),
            lambda r: _check_kconfig_quick(r, kconfig, profile_cfg),
        ):
            res = check_fn(rec)
            check_results.append(res)
            if res["result"] == RESULT_NOT_RELEVANT:
                break

        # Wrap into the same {cve, check_results} schema produced by `cve-triage triage`.
        reports.append(
            {
                "cve": {
                    "name": rec["name"],
                    "description": rec["description"],
                    "aliases": rec["aliases"],
                },
                "check_results": check_results,
            }
        )

    # Record analysis_level="quick" and null kernel_source_commit so downstream OpenVEX
    # consumers can distinguish fast version/config triage from compile-time kmax proof.
    return {
        "meta": {
            "analysis_level": "quick",
            "profile": profile_cfg.profile,
            "stable_branch": profile_cfg.stable_branch,
            "kernel_version": profile_cfg.parsed_version.raw,
            "kernel_arch": kconfig.detected_arch,
            "kernel_config_sha256": kconfig.raw_bytes_sha256,
            "sec_commit": catalog["sec_commit"],
            "kernel_source_commit": None,
            "tooling_pins": {
                "kernel_cve_triage": PINNED_KERNEL_CVE_TRIAGE_COMMIT,
                "kmax": PINNED_KMAX_VERSION,
            },
        },
        "reports": reports,
    }
