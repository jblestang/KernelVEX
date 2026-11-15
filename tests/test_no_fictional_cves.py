"""Guardrail tests ensuring zero fictional CVEs or handwritten catalogs exist in the repo."""

from __future__ import annotations

import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

# Build patterns dynamically so this file itself never embeds banned literal markers.
_FORBIDDEN_PATTERNS = [
    re.compile(r"\b" + "TEST" + r"-[0-9A-Za-z-]+\b"),
    re.compile(r"\bCVE-(?:" + "0000" + "|" + "9999" + "|" + "2099" + r")-[0-9]+\b"),
    re.compile("config_" + "any_of"),
]

_SCAN_DIRS = ("src", "tests", "ci", "docs", "schemas")
_SCAN_ROOT_FILES = ("README.md", "Dockerfile", "PINS.lock", "pyproject.toml")


def _iter_repo_text_files() -> list[Path]:
    files: list[Path] = []
    for rel_dir in _SCAN_DIRS:
        base = REPO_ROOT / rel_dir
        if not base.exists():
            continue
        for path in sorted(base.rglob("*")):
            if (
                path.is_file()
                and "__pycache__" not in path.parts
                and not any(part.endswith(".egg-info") for part in path.parts)
            ):
                files.append(path)
    for rel_file in _SCAN_ROOT_FILES:
        path = REPO_ROOT / rel_file
        if path.is_file():
            files.append(path)
    return files


def test_no_fictional_cves_or_handwritten_catalog_markers() -> None:
    """Verify no fictional CVE placeholders or handwritten Kconfig catalogs exist in repository."""
    violations: list[str] = []
    for file_path in _iter_repo_text_files():
        content = file_path.read_text(encoding="utf-8")
        for pat in _FORBIDDEN_PATTERNS:
            match = pat.search(content)
            if match is not None:
                rel = file_path.relative_to(REPO_ROOT)
                violations.append(f"{rel}: matched {match.group(0)!r}")
    assert not violations, f"Found forbidden fictional/manual CVE markers: {violations}"
