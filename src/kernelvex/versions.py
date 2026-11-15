"""Linux kernel and CIP SLTS version parsing and semantic comparison helpers.

Supports mainline tags (``v6.10-rc3``), Linux stable versions (``5.15.165``),
CIP SLTS tags (``v5.10.224-cip52``, ``v5.10.223-cip51-rt21``, ``v4.19-st1``),
and ``uname -r`` strings with vendor or distribution suffixes.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from functools import total_ordering

from kernelvex import KernelVexError

# Match leading major.minor[.patch] plus optional -rcN, -cipN, -rtN, or -stN tags.
# Distro/localversion suffixes (e.g. "-amd64", "+dirty") remain captured in raw.
_VERSION_RE = re.compile(
    r"^v?(?P<major>[0-9]+)\.(?P<minor>[0-9]+)"
    r"(?:\.(?P<patch>[0-9]+))?"
    r"(?:-rc(?P<rc>[0-9]+))?"
    r"(?:-cip(?P<cip>[0-9]+))?"
    r"(?:-rt(?P<rt>[0-9]+))?"
    r"(?:-st(?P<st>[0-9]+))?"
    r"(?:$|[-+._].*)"
)


@total_ordering
@dataclass(frozen=True)
class ParsedKernelVersion:
    """Structured representation of a Linux or CIP kernel version string.

    Attributes:
        major: Major kernel version number (e.g. ``5`` or ``6``).
        minor: Minor kernel series number (e.g. ``10``, ``15``, or ``1``).
        patch: Stable patch level, defaulting to ``0`` when omitted (e.g. ``v6.10-rc3``).
        rc: Release-candidate index if present, otherwise ``None``.
        cip: CIP release counter if present, otherwise ``None``.
        rt: CIP real-time release counter if present, otherwise ``None``.
        st: CIP security-tracking branch counter if present, otherwise ``None``.
        raw: Original unparsed version string preserved for reporting and PURLs.
    """

    major: int
    minor: int
    patch: int
    rc: int | None = None
    cip: int | None = None
    rt: int | None = None
    st: int | None = None
    raw: str = field(default="", compare=False)

    @property
    def sort_key(self) -> tuple[int, int, int, tuple[int, int], int, int, int]:
        """Return a total-order comparison key respecting Linux ``-rc`` semantics.

        Release candidates sort strictly *before* the corresponding final ``.0``
        release, while CIP/RT/ST suffixes sort monotonically within the same base.
        """
        # In Linux versioning, v6.10-rc4 precedes v6.10 (patch=0, rc=None).
        rc_order = (0, self.rc) if self.rc is not None else (1, 0)
        return (
            self.major,
            self.minor,
            self.patch,
            rc_order,
            self.cip if self.cip is not None else 0,
            self.rt if self.rt is not None else 0,
            self.st if self.st is not None else 0,
        )

    @property
    def series(self) -> tuple[int, int]:
        """Return the ``(major, minor)`` kernel series tuple."""
        return (self.major, self.minor)

    @property
    def is_cip(self) -> bool:
        """Return ``True`` when the version carries CIP-specific tags."""
        return self.cip is not None or self.st is not None

    def __eq__(self, other: object) -> bool:
        """Compare parsed versions by semantic ``sort_key`` rather than raw spelling."""
        if not isinstance(other, ParsedKernelVersion):
            return NotImplemented
        return self.sort_key == other.sort_key

    def __lt__(self, other: object) -> bool:
        """Order parsed versions chronologically using ``sort_key``."""
        if not isinstance(other, ParsedKernelVersion):
            return NotImplemented
        return self.sort_key < other.sort_key


def parse_kernel_version(raw: str) -> ParsedKernelVersion:
    """Parse a Linux or CIP kernel version string into ``ParsedKernelVersion``.

    Args:
        raw: Version string from CLI, ``uname -r``, git tag, or YAML metadata.

    Returns:
        A validated ``ParsedKernelVersion`` instance.

    Raises:
        KernelVexError: If ``raw`` is empty or does not begin with ``major.minor``.
    """
    cleaned = raw.strip()
    if not cleaned:
        raise KernelVexError("kernel_version must not be empty")

    # Reject non-kernel tracker tokens such as Ubuntu's "version:5.4.0-9.12".
    if ":" in cleaned:
        raise KernelVexError(f"Unsupported kernel version format: {raw!r}")

    match = _VERSION_RE.match(cleaned)
    if match is None:
        raise KernelVexError(f"Invalid kernel version string: {raw!r}")

    return ParsedKernelVersion(
        major=int(match.group("major")),
        minor=int(match.group("minor")),
        patch=int(match.group("patch")) if match.group("patch") is not None else 0,
        rc=int(match.group("rc")) if match.group("rc") is not None else None,
        cip=int(match.group("cip")) if match.group("cip") is not None else None,
        rt=int(match.group("rt")) if match.group("rt") is not None else None,
        st=int(match.group("st")) if match.group("st") is not None else None,
        raw=cleaned,
    )


def try_parse_kernel_version(raw: str) -> ParsedKernelVersion | None:
    """Best-effort version parser returning ``None`` instead of raising on odd tags.

    Used when scanning ``cip-kernel-sec`` YAML mappings (``fixed-version``,
    ``introduced-version``, ``affected-configs``) that may contain non-standard
    or vendor-specific string tokens such as distro epoch markers without failing
    an entire triage run.

    Args:
        raw: Candidate version string extracted from YAML metadata.

    Returns:
        Parsed ``ParsedKernelVersion`` when ``raw`` matches standard/CIP versioning,
        or ``None`` if the string cannot be ordered reliably.
    """
    try:
        return parse_kernel_version(raw)
    except KernelVexError:
        return None
