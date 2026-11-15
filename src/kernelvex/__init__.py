"""Industrial Linux kernel CVE triage and OpenVEX 0.2.0 orchestration package.

This package composes upstream OSS tooling without reimplementing any kernel
static analysis or vulnerability tracker:
- ``cip-kernel-sec`` as the single source of truth for kernel CVE YAML records;
- ``kernel-cve-triage`` (``cve-triage``) and ``kmax`` for compile-time checks;
- OpenVEX v0.2.0 JSON output enriched with CRA provenance metadata.

Design constraints enforced across all modules:
- Judge the effective kernel build (exact revision + effective ``.config``), never version alone.
- Reject non-standard CVE identifiers or manually authored Kconfig catalogs in production.
- Fail closed to ``under_investigation`` whenever upstream Kbuild/``kmax`` analysis errors out.
"""

from __future__ import annotations

# Package semantic version emitted in CLI `--version` and OpenVEX `tooling` strings.
__version__ = "0.1.0"

# Pinned upstream OSS references aligned with `PINS.lock` for auditable, reproducible CI runs.
# Keeping pins centralized ensures OpenVEX `meta.tooling_pins` matches the container image.
DEFAULT_SEC_REPO_URL = "https://gitlab.com/cip-project/cip-kernel/cip-kernel-sec.git"
DEFAULT_SEC_BRANCH = "master"
PINNED_KERNEL_CVE_TRIAGE_COMMIT = "3aa04484d7b0e58331d3da4b2aef78376f23de55"
PINNED_KMAX_VERSION = "4.10"

# Official OpenVEX v0.2.0 JSON-LD context IRI required by the upstream JSON Schema.
OPENVEX_CONTEXT_URL = "https://openvex.dev/ns/v0.2.0"

# Deterministic CI exit codes separating triage findings from tooling failures and gate breaches:
# - EXIT_OK (0): Zero open CVEs (`fixed` and/or `not_affected` only).
# - EXIT_OPEN_TRIAGE (10): Remaining `under_investigation`/`affected` with no gate breach.
# - EXIT_TOOL_ERROR (20): CLI usage error, missing input, git/kmax crash, or invalid VEX schema.
# - EXIT_POLICY_FAIL (30): `--fail-on` threshold breached for release-gating pipelines.
EXIT_OK = 0
EXIT_OPEN_TRIAGE = 10
EXIT_TOOL_ERROR = 20
EXIT_POLICY_FAIL = 30


class KernelVexError(Exception):
    """Domain or operational error that maps deterministically to exit code 20.

    Raised instead of raw ``SystemExit`` or unformatted tracebacks so CI logs
    always emit a single structured error message while returning ``EXIT_TOOL_ERROR``.
    """


__all__ = [
    "DEFAULT_SEC_BRANCH",
    "DEFAULT_SEC_REPO_URL",
    "EXIT_OK",
    "EXIT_OPEN_TRIAGE",
    "EXIT_POLICY_FAIL",
    "EXIT_TOOL_ERROR",
    "KernelVexError",
    "OPENVEX_CONTEXT_URL",
    "PINNED_KERNEL_CVE_TRIAGE_COMMIT",
    "PINNED_KMAX_VERSION",
    "__version__",
]
