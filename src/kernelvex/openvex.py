"""OpenVEX v0.2.0 serialization, JSON Schema validation, and CRA policy evaluation.

Aligns check-to-status mapping with ``kernel-cve-triage/scripts/convert_openvex.py``
while correcting two OpenVEX v0.2.0 specification discrepancies observed upstream:
1. Document ``version`` MUST be an integer (``1``), not a string (``"1"``).
2. ``products`` MUST reside inside each statement object rather than at the document root
   (which forbids unknown properties in upstream ``openvex_json_schema.json``).

Regulatory & CRA safety invariants:
- Any check reporting ``"unexpected failure"`` forces ``under_investigation`` across
  all checks for that CVE; a tooling or ``kmax`` failure never silently emits ``not_affected``.
- Unknown check names similarly fail closed to ``under_investigation``.
- Full git provenance (``sec_commit``, optional ``kernel_source_commit``) and effective
  ``.config`` SHA-256 are embedded in root ``meta`` (or sidecar under ``--strict-openvex``).
"""

from __future__ import annotations

import copy
import functools
import importlib.resources
import json
import re
from datetime import UTC, datetime
from typing import Any
from urllib.parse import quote, urlsplit

from jsonschema import Draft202012Validator
from packageurl import PackageURL
from packageurl.contrib import url2purl

from kernelvex import (
    EXIT_OK,
    EXIT_OPEN_TRIAGE,
    EXIT_POLICY_FAIL,
    OPENVEX_CONTEXT_URL,
    PINNED_KERNEL_CVE_TRIAGE_COMMIT,
    PINNED_KMAX_VERSION,
    KernelVexError,
    __version__,
)
from kernelvex.profile import ProfileConfig

# Canonical OpenVEX v0.2.0 status & justification string constants enforced by schema.
STATUS_NOT_AFFECTED = "not_affected"
STATUS_AFFECTED = "affected"
STATUS_FIXED = "fixed"
STATUS_UNDER_INVESTIGATION = "under_investigation"

# Justification required whenever status == "not_affected" and no impact_statement is given.
JUSTIFICATION_NOT_PRESENT = "vulnerable_code_not_present"

# Exact check names mapping to not_affected, aligned with convert_openvex.py plus quick mode.
# Any check outside NOT_AFFECTED_CHECKS or FIXED_CHECKS fails closed to under_investigation.
NOT_AFFECTED_CHECKS = frozenset(
    {
        "check_ignore",
        "check_introduced_by",
        "check_introduced_by_file_compiled",
        "check_fixed_by_file_compiled",
        "check_introduced_by_line_compiled",
        "check_kconfig_quick",
    }
)
# Check names proving the vulnerability commit or patch landed on the analyzed kernel branch.
FIXED_CHECKS = frozenset({"check_fixed_by"})

# Cryptographic digest validators enforcing full SHA-1/SHA-256 provenance integrity.
_HEX40_RE = re.compile(r"^[0-9a-f]{40}$")
_HEX64_RE = re.compile(r"^[0-9a-f]{64}$")


def _load_packaged_schema(filename: str) -> dict[str, Any]:
    """Load a bundled OpenVEX JSON Schema via ``importlib.resources``.

    Reads package-internal schema data instead of fragile relative repository paths
    so schema validation succeeds identically in wheels, containers, and editable installs.

    Args:
        filename: Schema filename under ``kernelvex/schemas/``.

    Returns:
        Decoded Draft 2020-12 JSON Schema dictionary.
    """
    schema_file = importlib.resources.files("kernelvex").joinpath("schemas", filename)
    return json.loads(schema_file.read_text(encoding="utf-8"))


def build_product_purl(
    kernel_url: str,
    kernel_version: str,
    kernel_arch: str,
    config_name: str,
    explicit_purl: str | None = None,
) -> str:
    """Build or validate an OpenVEX product Package URL (PURL) for the target kernel.

    Preserves exact SBOM component identifiers when ``explicit_purl`` is supplied,
    works around ``url2purl`` quirks on multi-segment GitLab subgroups and
    ``git.kernel.org`` URLs, and falls back deterministically to a generic kernel
    PURL for non-URL identifiers.

    Args:
        kernel_url: Kernel repository URL (e.g. CIP GitLab or ``git.kernel.org``).
        kernel_version: Target kernel version string attached as PURL version.
        kernel_arch: Architecture qualifier (e.g. ``x86_64``, ``aarch64``).
        config_name: Effective configuration basename qualifier (e.g. ``.config``).
        explicit_purl: Optional full PURL string overriding URL-derived synthesis.

    Returns:
        Canonical serialized PURL string suitable for OpenVEX ``products[].identifiers.purl``.

    Raises:
        KernelVexError: If ``explicit_purl`` fails strict Package URL parsing.
    """
    # Prefer explicit SBOM component PURL so downstream VEX-to-SPDX matching stays exact.
    if explicit_purl:
        try:
            parsed = PackageURL.from_string(explicit_purl)
        except ValueError as exc:
            raise KernelVexError(f"Invalid --product-purl {explicit_purl!r}: {exc}") from exc
        return str(parsed)

    # Normalize git remote URL segments and remove trailing .git suffix cleanly.
    qualifiers = {"arch": kernel_arch, "config": config_name}
    split_url = urlsplit(kernel_url)
    path_parts = [part for part in split_url.path.strip("/").split("/") if part]
    if path_parts and path_parts[-1].endswith(".git"):
        path_parts[-1] = path_parts[-1][:-4]

    # url2purl assumes two-segment repo paths and misparses GitLab subgroups
    # (e.g. treating linux-cip in cip-project/cip-kernel/linux-cip as version).
    host = split_url.netloc.lower()
    if host == "gitlab.com" and len(path_parts) >= 2:
        return str(
            PackageURL(
                type="gitlab",
                namespace="/".join(path_parts[:-1]),
                name=path_parts[-1],
                version=kernel_version,
                qualifiers=qualifiers,
            )
        )

    # url2purl maps git.kernel.org/.../linux.git to pkg:generic/linux.git?download_url=...;
    # canonicalize kernel.org URLs to match CIP/kernel SBOM conventions.
    if host == "kernel.org" or host.endswith(".kernel.org"):
        return str(
            PackageURL(
                type="generic",
                namespace="kernel.org",
                name="linux",
                version=kernel_version,
                qualifiers=qualifiers,
            )
        )

    # Delegate standard hosting URLs (GitHub, internal SSH/HTTPS git remotes) to url2purl,
    # overriding version and merging architecture + kernel config qualifiers cleanly.
    detected = url2purl.get_purl(kernel_url)
    if detected is not None:
        purl_dict = detected.to_dict()
        purl_dict["version"] = kernel_version
        merged_qualifiers = dict(purl_dict.get("qualifiers") or {})
        merged_qualifiers.update(qualifiers)
        purl_dict["qualifiers"] = merged_qualifiers
        return str(PackageURL(**purl_dict))

    # Last-resort fallback for non-URL local labels (e.g. bare identifier tokens).
    return str(
        PackageURL(
            type="generic",
            namespace="kernel.org",
            name="linux",
            version=kernel_version,
            qualifiers=qualifiers,
        )
    )


def _format_object_evidence(res: dict[str, Any]) -> str:
    """Format compiled/uncompiled Kmax object tuples from a check result.

    Args:
        res: Individual check result dictionary emitted by ``cve-triage``.

    Returns:
        Compact ``[objects: ...]`` suffix string, or empty string if absent.
    """
    objects = res.get("objects")
    if not isinstance(objects, list) or not objects:
        return ""
    parts: list[str] = []
    # Cap object evidence strings at 8 items to keep status_notes concise and readable.
    for obj in objects[:8]:
        if not isinstance(obj, dict):
            continue
        name = obj.get("name", "?")
        built = obj.get("built", "?")
        cfg = obj.get("config")
        parts.append(f"{name}(built={built}, config={cfg})")
    # Indicate truncation explicitly so auditors know full evidence lives in raw report JSON.
    if len(objects) > 8:
        parts.append(f"...+{len(objects) - 8} more")
    return f" [objects: {', '.join(parts)}]" if parts else ""


def map_cve_report_to_statement(
    obj: dict[str, Any],
    products: list[dict[str, Any]],
    analysis_level: str,
    policy_affected: bool = False,
) -> dict[str, Any]:
    """Convert one ``cve-triage`` / ``analyze quick`` report item into an OpenVEX statement.

    Guarantees CRA conservative behavior:
    - Any ``unexpected failure`` across ``check_results`` forces ``under_investigation``
      even if another check claimed ``not relevant``.
    - ``check_fixed_by`` emits ``fixed``.
    - Recognized exclusion checks emit ``not_affected`` with justification
      ``vulnerable_code_not_present`` and auditable ``status_notes``.
    - Unrecognized check names fail closed to ``under_investigation``.
    - Remaining unexcluded CVEs emit ``under_investigation`` (or ``affected`` when
      ``policy_affected=True``).

    Args:
        obj: Per-CVE report entry containing ``cve`` and ``check_results``.
        products: OpenVEX statement ``products`` list linking target PURL(s).
        analysis_level: ``"quick"`` or ``"full"`` tag included in ``status_notes``.
        policy_affected: Emit ``affected`` rather than ``under_investigation`` when open.

    Returns:
        Schema-compliant OpenVEX v0.2.0 statement dictionary.

    Raises:
        KernelVexError: If the report item is missing ``cve.name`` or ``check_results``.
    """
    cve = obj.get("cve")
    results = obj.get("check_results")
    if not isinstance(cve, dict) or not isinstance(results, list):
        raise KernelVexError("Malformed report entry: expected 'cve' dict and 'check_results' list")

    cve_name = str(cve.get("name") or "").strip()
    if not cve_name:
        raise KernelVexError("Malformed report entry: missing cve.name")

    vulnerability: dict[str, Any] = {
        "name": cve_name,
        "description": str(cve.get("description") or ""),
    }
    # Preserve upstream CVE aliases (e.g. CNAs/GHSA/OSV IDs) when present.
    raw_aliases = cve.get("aliases") or []
    aliases = list(dict.fromkeys(str(item) for item in raw_aliases if item))
    if aliases:
        vulnerability["aliases"] = aliases

    # Detect any check crashes ("unexpected failure") across the full check list.
    failed_checks = [
        str(res.get("name", "unknown"))
        for res in results
        if isinstance(res, dict) and res.get("result") == "unexpected failure"
    ]

    # Locate first short-circuiting "not relevant" check matching cve-triage evaluation.
    deciding_res: dict[str, Any] | None = None
    for res in results:
        if isinstance(res, dict) and res.get("result") == "not relevant":
            deciding_res = res
            break

    statement: dict[str, Any] = {
        "vulnerability": vulnerability,
        "products": products,
    }

    if failed_checks:
        # CRA safety guard: tool/kmax failure never produces a silent not_affected,
        # even if an earlier or sibling check claimed non-applicability.
        statement["status"] = STATUS_UNDER_INVESTIGATION
        statement["status_notes"] = (
            f"unexpected failure in {', '.join(failed_checks)}; manual review required "
            f"[analysis_level={analysis_level}]"
        )
        return statement

    if deciding_res is None:
        # All checks marked the CVE relevant (or no checks cleared it); summarize every check
        # reason and compiled object list so auditors can trace why the CVE remains open.
        summary_parts = []
        for res in results:
            if not isinstance(res, dict):
                continue
            name = str(res.get("name", "unknown"))
            reason = str(res.get("reason") or res.get("result") or "relevant")
            summary_parts.append(f"{name}: {reason}{_format_object_evidence(res)}")
        evidence = "; ".join(summary_parts) or "no check excluded CVE"

        if policy_affected:
            # Explicit policy opt-in marks unexcluded CVEs actionable via action_statement,
            # satisfying OpenVEX's required field constraint when status == "affected".
            statement["status"] = STATUS_AFFECTED
            statement["action_statement"] = (
                "Apply upstream stable/CIP kernel fix or disable vulnerable Kconfig subsystem."
            )
        else:
            statement["status"] = STATUS_UNDER_INVESTIGATION
        statement["status_notes"] = f"{evidence} [analysis_level={analysis_level}]"
        return statement

    check_name = str(deciding_res.get("name") or "")
    reason = str(deciding_res.get("reason") or "not relevant")
    obj_evidence = _format_object_evidence(deciding_res)

    if check_name in FIXED_CHECKS:
        # Commit/version verification proved the remediation landed on the target tree.
        statement["status"] = STATUS_FIXED
        statement["status_notes"] = f"{check_name}: {reason} [analysis_level={analysis_level}]"
    elif check_name in NOT_AFFECTED_CHECKS:
        # OpenVEX requires justification or impact_statement when status == not_affected;
        # embed exact Kmax object or check evidence inside status_notes for auditability.
        statement["status"] = STATUS_NOT_AFFECTED
        statement["justification"] = JUSTIFICATION_NOT_PRESENT
        statement["status_notes"] = (
            f"{check_name}: {reason}{obj_evidence} [analysis_level={analysis_level}]"
        )
    else:
        # Unknown upstream check name: fail safe instead of guessing not_affected so upgrades
        # to newer kernel-cve-triage versions never introduce silent unreviewed exclusions.
        statement["status"] = STATUS_UNDER_INVESTIGATION
        statement["status_notes"] = (
            f"unknown check {check_name!r} ({reason}); manual review required "
            f"[analysis_level={analysis_level}]"
        )

    return statement


def unpack_report_payload(payload: Any) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Accept either a raw ``cve-triage`` JSON list or a ``kernelvex`` report envelope.

    Args:
        payload: Parsed JSON data from ``analyze quick/full`` or raw ``cve-triage --out``.

    Returns:
        Tuple ``(reports_list, envelope_meta_dict)``.

    Raises:
        KernelVexError: If ``payload`` does not match either supported structure.
    """
    if isinstance(payload, list):
        return (payload, {})
    if isinstance(payload, dict) and isinstance(payload.get("reports"), list):
        meta = payload.get("meta")
        return (payload["reports"], meta if isinstance(meta, dict) else {})
    raise KernelVexError(
        "Invalid triage report JSON: expected list or {'meta': ..., 'reports': [...]}"
    )


@functools.lru_cache(maxsize=2)
def _load_validators(strict_openvex: bool) -> tuple[Draft202012Validator, Draft202012Validator]:
    """Return cached ``(fast_validator, full_validator)`` Draft 2020-12 instances.

    ``fast_validator`` drops only top-level ``statements.uniqueItems`` (which uses
    quadratic O(N^2) equality checks inside ``jsonschema``) while ``full_validator``
    retains the unmodified schema for fallback validation when duplicates appear.
    """
    schema_name = (
        "openvex_v0.2.0.upstream.schema.json"
        if strict_openvex
        else "openvex_v0.2.0_meta.schema.json"
    )
    full_schema = _load_packaged_schema(schema_name)
    fast_schema = copy.deepcopy(full_schema)
    # Preserve nested uniqueItems (products/aliases); only root statements scales to 10k+.
    fast_schema.get("properties", {}).get("statements", {}).pop("uniqueItems", None)
    return Draft202012Validator(fast_schema), Draft202012Validator(full_schema)


def validate_openvex_document(doc: dict[str, Any], strict_openvex: bool = False) -> None:
    """Validate an OpenVEX document against the bundled JSON Schema (exit 20 on error).

    Replaces ``jsonschema``'s quadratic O(N^2) pairwise ``uniqueItems`` check on root
    ``statements`` with an O(N) canonical-JSON digest set check, falling back to
    ``full_validator`` only when a duplicate or non-JSON value is detected.

    Args:
        doc: Assembled OpenVEX document dictionary.
        strict_openvex: Validate against unmodified upstream ``openvex_json_schema.json``
            when ``True``, or the ``meta``-extended schema when ``False``.

    Raises:
        KernelVexError: If JSON Schema validation fails at any path.
    """
    fast_validator, full_validator = _load_validators(strict_openvex)
    errors = sorted(fast_validator.iter_errors(doc), key=lambda err: list(err.path))
    if not errors:
        statements = doc.get("statements")
        if isinstance(statements, list):
            seen: set[str] = set()
            needs_full_check = False
            for stmt in statements:
                try:
                    digest = json.dumps(
                        stmt, sort_keys=True, separators=(",", ":"), allow_nan=False
                    )
                except (TypeError, ValueError):
                    needs_full_check = True
                    break
                if digest in seen:
                    needs_full_check = True
                    break
                seen.add(digest)
            if needs_full_check:
                # Re-run unmodified validator so duplicate/NaN errors match jsonschema formatting.
                errors = sorted(full_validator.iter_errors(doc), key=lambda err: list(err.path))

    if errors:
        first = errors[0]
        path_str = ".".join(str(part) for part in first.path) or "<root>"
        raise KernelVexError(f"OpenVEX schema validation failed at {path_str}: {first.message}")


def emit_openvex(
    report_payload: Any,
    profile_cfg: ProfileConfig,
    author: str,
    kernel_arch: str,
    config_name: str,
    kernel_config_sha256: str,
    sec_commit: str,
    kernel_source_commit: str | None = None,
    analysis_level: str = "full",
    kernel_url: str | None = None,
    explicit_purl: str | None = None,
    doc_id: str | None = None,
    role: str = "Automated Kernel CVE Triage Orchestrator",
    timestamp: str | None = None,
    policy_affected: bool = False,
    strict_openvex: bool = False,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Assemble and schema-validate an OpenVEX v0.2.0 document from triage reports.

    Validates all mandatory CRA provenance fields (40-char ``sec_commit``, 64-char
    ``kernel_config_sha256``, optional 40-char ``kernel_source_commit``), detects
    duplicate CVEs, sorts statements deterministically for clean CI diffs, and
    verifies the final payload against Draft 2020-12 JSON Schema before returning.

    Args:
        report_payload: Parsed report envelope or raw ``cve-triage`` array.
        profile_cfg: Active target profile and parsed kernel version.
        author: OpenVEX document author string.
        kernel_arch: Target architecture identifier for PURL and ``meta``.
        config_name: Configuration file basename attached to product PURL qualifier.
        kernel_config_sha256: Lowercase SHA-256 hex digest of uncompressed ``.config``.
        sec_commit: 40-char git commit SHA of ``cip-kernel-sec``.
        kernel_source_commit: Optional 40-char commit SHA of ``kernel_source``.
        analysis_level: ``"quick"`` or ``"full"`` (overridden by envelope metadata if present).
        kernel_url: Optional upstream git remote overriding profile default URL.
        explicit_purl: Optional SBOM PURL overriding URL-derived product PURL.
        doc_id: Optional explicit OpenVEX ``@id`` IRI.
        role: OpenVEX author role string.
        timestamp: Optional RFC-3339 issuance timestamp string.
        policy_affected: Map unexcluded CVEs to ``affected`` instead of ``under_investigation``.
        strict_openvex: Omit root ``meta`` and validate against strict upstream schema.

    Returns:
        Tuple ``(openvex_document, audit_meta)`` ready for atomic disk serialization.

    Raises:
        KernelVexError: On empty reports, duplicate CVEs, invalid provenance hashes,
            malformed PURLs, or JSON Schema violations.
    """
    reports, envelope_meta = unpack_report_payload(report_payload)
    if not reports:
        raise KernelVexError("Cannot emit OpenVEX document from an empty triage report")

    resolved_level = str(envelope_meta.get("analysis_level") or analysis_level)
    if resolved_level not in ("quick", "full"):
        raise KernelVexError(f"Invalid analysis_level {resolved_level!r}; expected 'quick'|'full'")

    # Enforce 40-char SHA provenance on sec_commit so every VEX binds to exact CVE state.
    resolved_sec_commit = str(envelope_meta.get("sec_commit") or sec_commit or "").lower()
    if not _HEX40_RE.match(resolved_sec_commit):
        raise KernelVexError(
            "Valid 40-char git SHA 'sec_commit' is required for OpenVEX audit provenance"
        )

    # Bind attestation cryptographically to the uncompressed kernel .config bytes.
    resolved_cfg_sha = str(
        envelope_meta.get("kernel_config_sha256") or kernel_config_sha256 or ""
    ).lower()
    if not _HEX64_RE.match(resolved_cfg_sha):
        raise KernelVexError(
            "Valid 64-char SHA-256 'kernel_config_sha256' is required for OpenVEX audit provenance"
        )

    # Full mode binds kernel_source_commit to exact HEAD SHA; quick mode permits None.
    raw_src_commit = kernel_source_commit or envelope_meta.get("kernel_source_commit")
    resolved_src_commit: str | None = str(raw_src_commit).lower() if raw_src_commit else None
    if resolved_src_commit is not None and not _HEX40_RE.match(resolved_src_commit):
        raise KernelVexError(f"Invalid 40-char git SHA kernel_source_commit: {raw_src_commit!r}")

    # Build OpenVEX product entry matching SBOM component identity via Package URL (PURL).
    effective_url = kernel_url or profile_cfg.default_kernel_url
    purl = build_product_purl(
        kernel_url=effective_url,
        kernel_version=profile_cfg.parsed_version.raw,
        kernel_arch=kernel_arch,
        config_name=config_name,
        explicit_purl=explicit_purl,
    )
    products = [{"@id": purl, "identifiers": {"purl": purl}}]

    # Convert each CVE entry independently while guarding against duplicate vulnerability IDs.
    statements: list[dict[str, Any]] = []
    seen_cves: set[str] = set()
    for entry in reports:
        stmt = map_cve_report_to_statement(
            entry,
            products=products,
            analysis_level=resolved_level,
            policy_affected=policy_affected,
        )
        cve_name = stmt["vulnerability"]["name"]
        if cve_name in seen_cves:
            raise KernelVexError(f"Duplicate CVE entry {cve_name!r} in triage report")
        seen_cves.add(cve_name)
        statements.append(stmt)

    # Sort statements deterministically by CVE ID so repeated CI runs produce stable diffs.
    statements.sort(key=lambda s: s["vulnerability"]["name"])

    # Default timestamp to UTC execution instant when caller omits reproducible override.
    issued_at = timestamp or datetime.now(UTC).isoformat()
    # Percent-encode non-IRI characters such as '+' in uname -r localversions (+dirty).
    safe_ver = quote(profile_cfg.parsed_version.raw, safe=".-_")
    resolved_doc_id = (
        doc_id
        or f"https://openvex.dev/docs/kernelvex/{profile_cfg.profile}/"
        f"{safe_ver}/{resolved_sec_commit[:12]}"
    )

    # Record complete cryptographic provenance: effective .config digest, sec commit,
    # kernel source SHA (null in quick mode), and upstream tool version pins from PINS.lock.
    audit_meta: dict[str, Any] = {
        "analysis_level": resolved_level,
        "profile": profile_cfg.profile,
        "stable_branch": profile_cfg.stable_branch,
        "kernel_version": profile_cfg.parsed_version.raw,
        "kernel_arch": kernel_arch,
        "kernel_config_sha256": resolved_cfg_sha,
        "sec_commit": resolved_sec_commit,
        "kernel_source_commit": resolved_src_commit,
        "tooling_pins": {
            "kernel_cve_triage": PINNED_KERNEL_CVE_TRIAGE_COMMIT,
            "kmax": PINNED_KMAX_VERSION,
        },
    }

    # Construct OpenVEX v0.2.0 root payload:
    # - `version` is integer 1 per schema (correcting upstream convert_openvex.py "1" string bug)
    # - `products` live inside every statement rather than at document root
    doc: dict[str, Any] = {
        "@context": OPENVEX_CONTEXT_URL,
        "@id": resolved_doc_id,
        "author": author,
        "role": role,
        "timestamp": issued_at,
        "version": 1,
        "tooling": (
            f"kernelvex/{__version__} "
            f"(kernel-cve-triage@{PINNED_KERNEL_CVE_TRIAGE_COMMIT[:12]}, "
            f"kmax=={PINNED_KMAX_VERSION})"
        ),
        "statements": statements,
    }
    if not strict_openvex:
        # Attach non-standard CRA provenance under `meta` validated by extended schema.
        doc["meta"] = audit_meta

    # Always validate against JSON Schema prior to returning so invalid VEX never hits disk.
    validate_openvex_document(doc, strict_openvex=strict_openvex)
    return (doc, audit_meta)


def evaluate_policy_exit_code(
    vex_doc: dict[str, Any], fail_on: str = "none"
) -> tuple[int, dict[str, int]]:
    """Compute CI exit code and per-status summary counts from an OpenVEX document.

    Exit codes:
        - ``0``: No ``under_investigation`` or ``affected`` statements remain.
        - ``10``: Triage open (``under_investigation`` or ``affected`` present) and
          no ``--fail-on`` policy threshold breached.
        - ``30``: ``--fail-on`` policy threshold breached.

    Args:
        vex_doc: Validated OpenVEX v0.2.0 document dictionary.
        fail_on: Policy gate mode (``"none"``, ``"under_investigation"``, ``"affected"``).

    Returns:
        Tuple ``(exit_code, per_status_counts)``.

    Raises:
        KernelVexError: If ``fail_on`` is outside the supported policy modes.
    """
    if fail_on not in ("none", "under_investigation", "affected"):
        raise KernelVexError(
            f"Invalid --fail-on value {fail_on!r}; "
            "expected 'none', 'under_investigation', or 'affected'"
        )

    # Aggregate counts per canonical OpenVEX v0.2.0 status across all statements.
    counts = {
        STATUS_NOT_AFFECTED: 0,
        STATUS_FIXED: 0,
        STATUS_UNDER_INVESTIGATION: 0,
        STATUS_AFFECTED: 0,
    }
    for stmt in vex_doc.get("statements", []):
        status = stmt.get("status")
        if status in counts:
            counts[status] += 1

    # Open triage encompasses both unverified investigations and confirmed affected items.
    open_count = counts[STATUS_UNDER_INVESTIGATION] + counts[STATUS_AFFECTED]

    # Enforce strict release gates before advisory open-triage reporting:
    # - --fail-on under_investigation blocks if ANY CVE stays open (strict CRA gate).
    # - --fail-on affected blocks only when policy explicitly marked CVEs as affected.
    # - --fail-on none distinguishes open triage (exit 10) from completely clean (exit 0).
    if fail_on == "under_investigation" and open_count > 0:
        return (EXIT_POLICY_FAIL, counts)
    if fail_on == "affected" and counts[STATUS_AFFECTED] > 0:
        return (EXIT_POLICY_FAIL, counts)
    if open_count > 0:
        return (EXIT_OPEN_TRIAGE, counts)
    return (EXIT_OK, counts)
