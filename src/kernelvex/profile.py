"""Profile resolution and CVE branch applicability for CIP and standard kernels.

Supports both CIP SLTS trees (``linux-cip``, ``*-cipN``) and upstream/vendor
Linux trees (``stable/*``, ``mainline``) through a single parameterised model.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Literal

from kernelvex import KernelVexError
from kernelvex.versions import ParsedKernelVersion, parse_kernel_version

ProfileName = Literal["cip", "standard"]

DEFAULT_CIP_KERNEL_URL = "https://gitlab.com/cip-project/cip-kernel/linux-cip"
DEFAULT_STANDARD_KERNEL_URL = "https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git"


@dataclass(frozen=True)
class ProfileConfig:
    """Resolved execution profile controlling branch selection and ``cve-triage`` flags.

    Attributes:
        profile: Selected profile (``"cip"`` or ``"standard"``).
        stable_branch: Branch selector key in ``cip-kernel-sec`` YAML
            (e.g. ``"cip/5.10"`` or ``"stable/5.15"``).
        default_kernel_url: Upstream git URL used as PURL fallback when no custom
            ``--kernel-url`` or ``--product-purl`` is supplied.
        use_cip_flag: Whether ``cve-triage`` must be invoked with ``--cip``.
        parsed_version: Parsed structural representation of the target kernel.
    """

    profile: ProfileName
    stable_branch: str
    default_kernel_url: str
    use_cip_flag: bool
    parsed_version: ParsedKernelVersion


def _derive_stable_branch(profile: ProfileName, parsed: ParsedKernelVersion) -> str:
    """Infer the default ``cip-kernel-sec`` branch key from profile and version."""
    series = f"{parsed.major}.{parsed.minor}"
    if profile == "cip":
        # Preserve -rt and -st CIP sub-branches so ignore/fixed keys match accurately.
        if parsed.rt is not None:
            return f"cip/{series}-rt"
        if parsed.st is not None:
            return f"cip/{series}-st"
        return f"cip/{series}"
    return f"stable/{series}"


def resolve_profile(
    explicit_profile: str | None,
    kernel_version: str,
    stable_branch: str | None = None,
) -> ProfileConfig:
    """Resolve ``cip`` vs ``standard`` profile and canonical branch name.

    Auto-detection selects ``cip`` whenever the kernel version contains ``-cipN``
    or ``-stN``, or when ``--stable-branch`` begins with ``cip/``. Explicit
    ``--profile cip`` or ``--profile standard`` overrides auto-detection while
    still validating ``kernel_version`` and ``stable_branch``.

    Args:
        explicit_profile: ``"cip"``, ``"standard"``, ``"auto"``, or ``None``.
        kernel_version: Target kernel version or tag (e.g. ``v5.10.224-cip52``).
        stable_branch: Optional explicit branch key (e.g. ``stable/5.15``).

    Returns:
        Populated ``ProfileConfig`` instance.

    Raises:
        KernelVexError: If ``explicit_profile`` or ``kernel_version`` is invalid.
    """
    parsed = parse_kernel_version(kernel_version)

    if explicit_profile is not None and explicit_profile not in ("auto", "cip", "standard"):
        raise KernelVexError(
            f"Invalid profile {explicit_profile!r}; expected 'cip', 'standard', or 'auto'"
        )

    cleaned_branch = stable_branch.strip() if stable_branch is not None else ""
    if stable_branch is not None and not cleaned_branch:
        raise KernelVexError("stable_branch must not be blank when provided")

    # Auto-detect CIP when tag carries CIP/ST markers or branch starts with cip/.
    if explicit_profile in (None, "auto"):
        if parsed.is_cip or cleaned_branch.startswith("cip/"):
            selected: ProfileName = "cip"
        else:
            selected = "standard"
    else:
        selected = explicit_profile  # type: ignore[assignment]

    branch = cleaned_branch or _derive_stable_branch(selected, parsed)
    default_url = DEFAULT_CIP_KERNEL_URL if selected == "cip" else DEFAULT_STANDARD_KERNEL_URL

    return ProfileConfig(
        profile=selected,
        stable_branch=branch,
        default_kernel_url=default_url,
        use_cip_flag=(selected == "cip"),
        parsed_version=parsed,
    )


def _collect_branch_keys(cve_record: dict[str, Any]) -> set[str]:
    """Collect all branch keys declared across version and commit mappings."""
    keys: set[str] = set()
    for field_name in ("introduced_by", "introduced_version", "fixed_by", "fixed_version"):
        mapping = cve_record.get(field_name)
        if isinstance(mapping, dict):
            keys.update(str(k) for k in mapping.keys())
    return keys


def is_cve_applicable_to_profile(cve_record: dict[str, Any], profile: ProfileName) -> bool:
    """Return whether a CVE catalog record is in scope for ``profile``.

    Per specification section 3, when running under the ``standard`` profile on
    upstream/distro trees, entries whose branch metadata targets exclusively
    ``cip/*`` branches (with no ``mainline`` or ``stable/*`` keys) are ignored.

    Args:
        cve_record: Canonical CVE dictionary stored in ``catalog.json``.
        profile: Active profile (``"cip"`` or ``"standard"``).

    Returns:
        ``True`` if the CVE should be evaluated under ``profile``.
    """
    if profile == "cip":
        return True

    branch_keys = _collect_branch_keys(cve_record)
    if not branch_keys:
        # Preserve entries lacking branch metadata so triage stays conservative.
        return True

    # Ignore CIP-only entries when targeting standard stable/mainline kernels.
    has_standard_or_mainline = any(
        key == "mainline" or key.startswith("stable/") for key in branch_keys
    )
    has_cip = any(key.startswith("cip/") for key in branch_keys)
    if has_cip and not has_standard_or_mainline:
        return False

    return True
