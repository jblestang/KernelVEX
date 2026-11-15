"""Tests for catalog refresh, merge-enrich, and conservative analyze quick mode."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

from kernelvex import KernelVexError
from kernelvex.catalog import merge_enriched_dir, refresh_catalog
from kernelvex.kconfig import load_kconfig
from kernelvex.profile import resolve_profile
from kernelvex.quick import run_quick_analysis

FIXTURES = Path(__file__).resolve().parent / "fixtures"


def _init_local_sec_git_repo(dest: Path) -> Path:
    """Create a real local git repository from pinned upstream cip-kernel-sec fixtures."""
    shutil.copytree(FIXTURES / "sec", dest)
    subprocess.run(["git", "init", "-b", "master", str(dest)], check=True, capture_output=True)
    subprocess.run(
        ["git", "-C", str(dest), "config", "user.email", "ci@example.org"],
        check=True,
        capture_output=True,
    )
    subprocess.run(
        ["git", "-C", str(dest), "config", "user.name", "CI"],
        check=True,
        capture_output=True,
    )
    subprocess.run(["git", "-C", str(dest), "add", "."], check=True, capture_output=True)
    subprocess.run(
        ["git", "-C", str(dest), "commit", "-m", "fixture snapshot"],
        check=True,
        capture_output=True,
    )
    return dest


def test_catalog_refresh_merge_enrich_and_quick_cip(tmp_path: Path) -> None:
    sec_repo = _init_local_sec_git_repo(tmp_path / "upstream-sec")
    cache_dir = tmp_path / "cache"

    catalog = refresh_catalog(cache_dir=cache_dir, sec_url=str(sec_repo), sec_ref="master")
    assert catalog["cve_count"] == 6
    assert len(catalog["sec_commit"]) == 40

    # Second refresh at identical commit hits fast path without re-parsing.
    catalog_cached = refresh_catalog(cache_dir=cache_dir, sec_url=str(sec_repo), sec_ref="master")
    assert catalog_cached["refreshed_at"] == catalog["refreshed_at"]

    # Simulate cve-triage enrich YAML output for CVE-2024-40901 and CVE-2024-44934.
    enriched_dir = tmp_path / "enriched"
    enriched_dir.mkdir()
    (enriched_dir / "CVE-2024-40901.yml").write_text(
        yaml.safe_dump(
            {
                "name": "CVE-2024-40901",
                "affected-files": {"v5.10.224-cip52": ["drivers/scsi/mpt3sas/mpt3sas_ctl.c"]},
                "affected-configs": {"v5.10.224-cip52": ["(CONFIG_SCSI_MPT3SAS)"]},
            }
        ),
        encoding="utf-8",
    )
    (enriched_dir / "CVE-2024-44934.yml").write_text(
        yaml.safe_dump(
            {
                "name": "CVE-2024-44934",
                "affected-files": {"v5.10.224-cip52": ["net/bridge/br_multicast.c"]},
                "affected-configs": {"v5.10.224-cip52": ["(CONFIG_BRIDGE)"]},
            }
        ),
        encoding="utf-8",
    )
    merged = merge_enriched_dir(cache_dir, enriched_dir)
    assert merged["enriched_merged_count"] == 2

    kconfig = load_kconfig(FIXTURES / "configs" / "5.10.y-cip_x86_cip_merged_defconfig")
    profile_cfg = resolve_profile("cip", "v5.10.224-cip52")
    envelope = run_quick_analysis(catalog=merged, kconfig=kconfig, profile_cfg=profile_cfg)

    assert envelope["meta"]["analysis_level"] == "quick"
    assert envelope["meta"]["kernel_source_commit"] is None

    by_cve = {item["cve"]["name"]: item["check_results"] for item in envelope["reports"]}
    # CVE-2024-39496: ignore.cip/5.10 -> not relevant via check_ignore
    assert by_cve["CVE-2024-39496"][-1]["name"] == "check_ignore"
    assert by_cve["CVE-2024-39496"][-1]["result"] == "not relevant"
    # CVE-2024-50246: introduced in v5.15-rc1 -> out of range for 5.10
    assert by_cve["CVE-2024-50246"][-1]["name"] == "check_introduced_by"
    assert by_cve["CVE-2024-50246"][-1]["result"] == "not relevant"
    # CVE-2024-40990 and CVE-2024-40901: fixed by v5.10.221-cip50 <= v5.10.224-cip52
    assert by_cve["CVE-2024-40990"][-1]["name"] == "check_fixed_by"
    assert by_cve["CVE-2024-40990"][-1]["result"] == "not relevant"
    assert by_cve["CVE-2024-40901"][-1]["name"] == "check_fixed_by"
    assert by_cve["CVE-2024-40901"][-1]["result"] == "not relevant"
    # CVE-2024-44934: CONFIG_BRIDGE=y in defconfig -> active CONFIG stays under_investigation
    assert "CONFIG_BRIDGE" in kconfig.enabled_options
    assert by_cve["CVE-2024-44934"][-1]["name"] == "check_kconfig_quick"
    assert by_cve["CVE-2024-44934"][-1]["result"] == "relevant"
    # CVE-2024-44958: unenriched, unfixed -> relevant/under_investigation
    assert by_cve["CVE-2024-44958"][-1]["result"] == "relevant"

    # Evaluate earlier unfixed CIP build (v5.10.220-cip49 < v5.10.221-cip50):
    # CVE-2024-40901 falls through check_fixed_by to enriched check_kconfig_quick and
    # is excluded because CONFIG_SCSI_MPT3SAS is disabled in defconfig.
    older_profile = resolve_profile("cip", "v5.10.220-cip49")
    older_env = run_quick_analysis(catalog=merged, kconfig=kconfig, profile_cfg=older_profile)
    older_by_cve = {item["cve"]["name"]: item["check_results"] for item in older_env["reports"]}
    assert older_by_cve["CVE-2024-40901"][-1]["name"] == "check_kconfig_quick"
    assert older_by_cve["CVE-2024-40901"][-1]["result"] == "not relevant"
    assert older_by_cve["CVE-2024-44934"][-1]["name"] == "check_kconfig_quick"
    assert older_by_cve["CVE-2024-44934"][-1]["result"] == "relevant"


def test_quick_standard_profile_ignores_cip_only_and_checks_stable_fixed(tmp_path: Path) -> None:
    sec_repo = _init_local_sec_git_repo(tmp_path / "upstream-sec")
    cache_dir = tmp_path / "cache"
    catalog = refresh_catalog(cache_dir=cache_dir, sec_url=str(sec_repo), sec_ref="master")

    kconfig = load_kconfig(FIXTURES / "configs" / "5.15.y_x86_cip_merged_defconfig")
    profile_cfg = resolve_profile("standard", "5.15.165", stable_branch="stable/5.15")
    envelope = run_quick_analysis(catalog=catalog, kconfig=kconfig, profile_cfg=profile_cfg)

    by_cve = {item["cve"]["name"]: item["check_results"] for item in envelope["reports"]}
    # Fixed in stable/5.15 at v5.15.165 -> fixed
    assert by_cve["CVE-2024-44934"][-1]["name"] == "check_fixed_by"
    assert by_cve["CVE-2024-44934"][-1]["result"] == "not relevant"
    assert by_cve["CVE-2024-44958"][-1]["name"] == "check_fixed_by"
    assert by_cve["CVE-2024-44958"][-1]["result"] == "not relevant"
    # Introduced in 5.15-rc1, NOT fixed in stable/5.15 -> stays relevant
    assert by_cve["CVE-2024-50246"][-1]["result"] == "relevant"

    with pytest.raises(KernelVexError):
        merge_enriched_dir(cache_dir, tmp_path / "does-not-exist")
