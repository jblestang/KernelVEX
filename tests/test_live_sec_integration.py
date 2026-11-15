"""Live integration test pulling public cip-kernel-sec and running CI quick pipelines."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from kernelvex import EXIT_OK, EXIT_OPEN_TRIAGE, EXIT_POLICY_FAIL
from kernelvex.cli import main
from kernelvex.openvex import validate_openvex_document

FIXTURES = Path(__file__).resolve().parent / "fixtures"


@pytest.mark.live_network
def test_live_catalog_refresh_and_dual_profile_ci_pipeline(tmp_path: Path) -> None:
    """Verify catalog refresh from public cip-kernel-sec and CIP/standard CI pipelines."""
    cache_dir = tmp_path / "cache"

    # Definition of Done #1: catalog refresh from public cip-kernel-sec with empty cache.
    rc_refresh = main(["--cache-dir", str(cache_dir), "catalog", "refresh"])
    assert rc_refresh == EXIT_OK
    catalog = json.loads((cache_dir / "catalog.json").read_text(encoding="utf-8"))
    assert catalog["cve_count"] > 1000
    assert len(catalog["sec_commit"]) == 40

    # Profile CIP quick pipeline on real linux-cip version + real CIP merged defconfig.
    cip_vex_path = tmp_path / "cip.vex.json"
    rc_cip = main(
        [
            "ci",
            "pipeline",
            "--cache-dir",
            str(cache_dir),
            "--skip-refresh",
            "--profile",
            "cip",
            "--kernel-version",
            "v5.10.224-cip52",
            "--kernel-config",
            str(FIXTURES / "configs" / "5.10.y-cip_x86_cip_merged_defconfig"),
            "--stable-branch",
            "cip/5.10",
            "--mode",
            "quick",
            "--cve-id",
            "CVE-2024-40990",
            "CVE-2024-39496",
            "CVE-2024-44958",
            "--output",
            str(cip_vex_path),
        ]
    )
    assert rc_cip == EXIT_OPEN_TRIAGE
    cip_vex = json.loads(cip_vex_path.read_text(encoding="utf-8"))
    validate_openvex_document(cip_vex, strict_openvex=False)
    assert cip_vex["meta"]["sec_commit"] == catalog["sec_commit"]
    assert cip_vex["meta"]["analysis_level"] == "quick"
    cip_by_cve = {s["vulnerability"]["name"]: s for s in cip_vex["statements"]}
    assert cip_by_cve["CVE-2024-40990"]["status"] == "fixed"
    assert cip_by_cve["CVE-2024-39496"]["status"] == "not_affected"
    assert cip_by_cve["CVE-2024-44958"]["status"] == "under_investigation"

    # Profile standard quick pipeline on stable 5.15 with --fail-on policy enforcement.
    std_vex_path = tmp_path / "std.vex.json"
    rc_std = main(
        [
            "ci",
            "pipeline",
            "--cache-dir",
            str(cache_dir),
            "--skip-refresh",
            "--profile",
            "standard",
            "--kernel-version",
            "5.15.165",
            "--kernel-config",
            str(FIXTURES / "configs" / "5.15.y_x86_cip_merged_defconfig"),
            "--stable-branch",
            "stable/5.15",
            "--mode",
            "quick",
            "--cve-since-year",
            "2024",
            "--fail-on",
            "under_investigation",
            "--output",
            str(std_vex_path),
        ]
    )
    assert rc_std == EXIT_POLICY_FAIL
    std_vex = json.loads(std_vex_path.read_text(encoding="utf-8"))
    validate_openvex_document(std_vex, strict_openvex=False)
    assert std_vex["meta"]["profile"] == "standard"
    assert len(std_vex["statements"]) > 100
