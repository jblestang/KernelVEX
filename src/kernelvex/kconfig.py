"""Linux Kconfig parsing (``.config`` / ``config.gz``) and Kmax formula evaluation.

Parses effective build configurations (``=y``, ``=m``, values, unset options),
infers target architecture for OpenVEX PURLs and Kbuild ``ARCH``, and evaluates
boolean Kconfig formulas produced by ``kmax`` / ``cve-triage enrich``.
"""

from __future__ import annotations

import gzip
import hashlib
import re
from collections.abc import Set as AbstractSet
from dataclasses import dataclass
from pathlib import Path

from kernelvex import KernelVexError

# Match active Kconfig assignments such as CONFIG_NET=y, CONFIG_FOO=m, or strings.
_CONFIG_ASSIGN_RE = re.compile(r"^(CONFIG_[A-Za-z0-9_]+)=(.+)$")

# Tokenizer pattern for boolean expressions emitted by cve_triage.triage.kmax.BoolExpression.
_EXPR_TOKEN_RE = re.compile(r"\s*(&&|\|\||!|\(|\)|CONFIG_[A-Za-z0-9_]+(?:=[ymn])?|True|False)\s*")


@dataclass(frozen=True)
class LoadedKconfig:
    """Normalized Kconfig snapshot and cryptographic audit digest.

    Attributes:
        enabled_options: Set of enabled ``CONFIG_*`` symbols (``=y``, ``=m``, or
            configured scalar/string values; excludes ``is not set`` and ``=n``).
        raw_bytes_sha256: Lowercase hex SHA-256 of the uncompressed UTF-8 ``.config``.
        detected_arch: OpenVEX PURL architecture qualifier (e.g. ``x86_64``, ``aarch64``).
        make_arch: Linux Kbuild ``ARCH`` variable (e.g. ``x86``, ``arm64``, ``riscv``).
        plain_text: Uncompressed configuration text suitable for ``make alldefconfig``.
    """

    enabled_options: frozenset[str]
    raw_bytes_sha256: str
    detected_arch: str
    make_arch: str
    plain_text: str


def _infer_arches(enabled_options: AbstractSet[str]) -> tuple[str, str]:
    """Infer ``(purl_arch, kbuild_make_arch)`` from top-level architecture symbols.

    Returns a pair separating the OpenVEX PURL/distro architecture identifier
    (e.g. ``aarch64``, ``x86_64``, ``riscv64``) from the Linux Kbuild ``ARCH``
    environment variable expected by ``make alldefconfig`` (e.g. ``arm64``,
    ``x86``, ``riscv``). Defaults conservatively to ``("x86_64", "x86")`` if no
    architecture symbol is present (e.g. minimal Kconfig fragments).

    Args:
        enabled_options: Set of active ``CONFIG_*`` symbol names.

    Returns:
        Tuple ``(purl_arch, make_arch)``.
    """
    # Check 64-bit / specific architecture symbols before broader family symbols
    # because 64-bit kernels typically define both CONFIG_X86_64 and CONFIG_X86.
    if "CONFIG_X86_64" in enabled_options:
        return ("x86_64", "x86")
    if "CONFIG_X86_32" in enabled_options or "CONFIG_X86" in enabled_options:
        return ("x86", "x86")
    if "CONFIG_ARM64" in enabled_options:
        return ("aarch64", "arm64")
    if "CONFIG_ARM" in enabled_options:
        return ("arm", "arm")
    if "CONFIG_RISCV" in enabled_options:
        # Treat 64-bit RISC-V as the common industrial default unless 32-bit is explicit.
        purl_arch = "riscv32" if "CONFIG_32BIT" in enabled_options else "riscv64"
        return (purl_arch, "riscv")
    if "CONFIG_PPC64" in enabled_options:
        return ("ppc64", "powerpc")
    if "CONFIG_PPC" in enabled_options:
        return ("ppc", "powerpc")
    if "CONFIG_S390" in enabled_options:
        return ("s390x", "s390")
    if "CONFIG_MIPS" in enabled_options:
        return ("mips", "mips")
    return ("x86_64", "x86")


def load_kconfig(path: Path) -> LoadedKconfig:
    """Load and parse a plain ``.config`` or gzipped ``/proc/config.gz`` file.

    Args:
        path: Filesystem path to the kernel configuration file.

    Returns:
        ``LoadedKconfig`` containing enabled options, SHA-256 digest, and arch.

    Raises:
        KernelVexError: If the file is missing, unreadable, or invalid gzip/UTF-8.
    """
    if not path.is_file():
        raise KernelVexError(f"Kernel config file does not exist: {path}")

    try:
        raw_bytes = path.read_bytes()
    except OSError as exc:
        raise KernelVexError(f"Failed to read kernel config {path}: {exc}") from exc

    # Support /proc/config.gz exports by checking gzip magic header (1f 8b) or .gz suffix.
    if raw_bytes.startswith(b"\x1f\x8b") or path.suffix == ".gz":
        try:
            plain_bytes = gzip.decompress(raw_bytes)
        except (OSError, EOFError) as exc:
            raise KernelVexError(f"Failed to decompress gzipped config {path}: {exc}") from exc
    else:
        plain_bytes = raw_bytes

    try:
        plain_text = plain_bytes.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise KernelVexError(f"Kernel config {path} is not valid UTF-8 text: {exc}") from exc

    digest = hashlib.sha256(plain_bytes).hexdigest()
    enabled: set[str] = set()

    for raw_line in plain_text.splitlines():
        line = raw_line.strip()
        # Skip empty lines and comments including "# CONFIG_FOO is not set".
        if not line or line.startswith("#"):
            continue
        match = _CONFIG_ASSIGN_RE.match(line)
        if match is None:
            continue
        symbol, value = match.group(1), match.group(2).strip()
        # Any value other than explicit "n" enables or configures the Kconfig symbol.
        if value != "n":
            enabled.add(symbol)

    frozen_enabled = frozenset(enabled)
    purl_arch, make_arch = _infer_arches(frozen_enabled)

    return LoadedKconfig(
        enabled_options=frozen_enabled,
        raw_bytes_sha256=digest,
        detected_arch=purl_arch,
        make_arch=make_arch,
        plain_text=plain_text,
    )


class _BoolExprParser:
    """Recursive-descent parser for Kmax boolean presence condition strings.

    Implements standard C/Kconfig operator precedence (``!`` unary negation >
    ``&&`` conjunction > ``||`` disjunction) without invoking Python ``eval``,
    ensuring malformed or untrusted expression strings fail deterministically.
    """

    def __init__(self, tokens: list[str], enabled_options: AbstractSet[str]) -> None:
        """Initialize parser state for a pre-tokenized boolean expression.

        Args:
            tokens: Ordered lexical tokens extracted from ``_EXPR_TOKEN_RE``.
            enabled_options: Enabled ``CONFIG_*`` symbol set for the target kernel.
        """
        self._tokens = tokens
        self._pos = 0
        self._enabled = enabled_options

    def parse(self) -> bool:
        """Evaluate the tokenized expression and ensure full token consumption.

        Returns:
            Evaluated truth value of the boolean presence expression.

        Raises:
            ValueError: If token stream is empty, unbalanced, or contains trailing tokens.
        """
        if not self._tokens:
            raise ValueError("Empty boolean expression")
        value = self._parse_or()
        if self._pos != len(self._tokens):
            raise ValueError(f"Unexpected trailing token: {self._tokens[self._pos]!r}")
        return value

    def _peek(self) -> str | None:
        """Return the current lookahead token without advancing cursor."""
        return self._tokens[self._pos] if self._pos < len(self._tokens) else None

    def _consume(self) -> str:
        """Consume and return the current token, advancing cursor by one."""
        tok = self._tokens[self._pos]
        self._pos += 1
        return tok

    def _parse_or(self) -> bool:
        """Parse left-associative disjunctions (``A || B``, lowest precedence)."""
        # Evaluate left-associative disjunctions (lowest precedence).
        left = self._parse_and()
        while self._peek() == "||":
            self._consume()
            right = self._parse_and()
            left = left or right
        return left

    def _parse_and(self) -> bool:
        """Parse left-associative conjunctions (``A && B``, binds tighter than ``||``)."""
        # Evaluate left-associative conjunctions (higher precedence than ||).
        left = self._parse_unary()
        while self._peek() == "&&":
            self._consume()
            right = self._parse_unary()
            left = left and right
        return left

    def _parse_unary(self) -> bool:
        """Parse right-recursive unary negation (``!expr``)."""
        if self._peek() == "!":
            self._consume()
            return not self._parse_unary()
        return self._parse_atom()

    def _parse_atom(self) -> bool:
        """Parse parenthesized subexpressions, boolean literals, and ``CONFIG_*`` atoms."""
        tok = self._peek()
        if tok is None:
            raise ValueError("Unexpected end of boolean expression")
        if tok == "(":
            self._consume()
            inner = self._parse_or()
            if self._peek() != ")":
                raise ValueError("Unbalanced parentheses in boolean expression")
            self._consume()
            return inner
        if tok in ("&&", "||", ")"):
            raise ValueError(f"Unexpected operator or delimiter: {tok!r}")

        self._consume()
        if tok == "True":
            return True
        if tok == "False":
            return False
        if "=" in tok:
            # Handle optional Kconfig value qualifier such as CONFIG_FOO=y.
            sym, _, val = tok.partition("=")
            return (sym not in self._enabled) if val == "n" else (sym in self._enabled)
        return tok in self._enabled


def eval_kmax_config_expr(expr: str, enabled_options: AbstractSet[str]) -> bool:
    """Evaluate a Kmax ``BoolExpression`` string against active Kconfig symbols.

    Supports ``&&``, ``||``, ``!``, parentheses, ``True``, ``False``, and
    ``CONFIG_*`` literals as emitted by ``cve-triage enrich``.

    Args:
        expr: Boolean Kconfig constraint expression string.
        enabled_options: Set of enabled ``CONFIG_*`` symbols from ``.config``.

    Returns:
        Boolean result indicating whether the build constraint is satisfied.

    Raises:
        ValueError: If ``expr`` is empty, contains unrecognized tokens, or has
            malformed boolean syntax.
    """
    stripped = expr.strip()
    if not stripped:
        raise ValueError("Empty Kconfig expression")

    tokens: list[str] = []
    pos = 0
    while pos < len(stripped):
        match = _EXPR_TOKEN_RE.match(stripped, pos)
        if match is None:
            raise ValueError(f"Unrecognized syntax in Kconfig expression at offset {pos}: {expr!r}")
        tokens.append(match.group(1))
        pos = match.end()

    return _BoolExprParser(tokens, enabled_options).parse()
