"""Golden-file, OpenVEX 0.2.0 schema, safety guard, and CI exit code tests."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from kernelvex import EXIT_OK, EXIT_OPEN_TRIAGE, EXIT_POLICY_FAIL, EXIT_TOOL_ERROR, KernelVexError
from kernelvex.cli import main
from kernelvex.kconfig import load_kconfig
from kernelvex.openvex import (
    build_product_purl,
    emit_openvex,
    evaluate_policy_exit_code,
    validate_openvex_document,
)
from kernelvex.profile import resolve_profile

REPO_ROOT = Path(__file__).resolve().parent.parent
FIXTURES = REPO_ROOT / "tests" / "fixtures"


def test_bundled_schemas_match_root_schemas_byte_for_byte() -> None:
    for name in ("openvex_v0.2.0.upstream.schema.json", "openvex_v0.2.0_meta.schema.json"):
        root_bytes = (REPO_ROOT / "schemas" / name).read_bytes()
        pkg_bytes = (REPO_ROOT / "src" / "kernelvex" / "schemas" / name).read_bytes()
        assert pkg_bytes == root_bytes


def test_golden_openvex_cip_full_and_strict_upstream_schema(tmp_path: Path) -> None:
    out_file = tmp_path / "openvex.json"
    exit_code = main(
        [
            "vex",
            "emit",
            "--profile",
            "cip",
            "--kernel-version",
            "v5.10.224-cip52",
            "--kernel-config",
            str(FIXTURES / "configs" / "5.10.y-cip_x86_cip_merged_defconfig"),
            "--stable-branch",
            "cip/5.10",
            "--report",
            str(FIXTURES / "reports" / "cve_triage_v5.10.224-cip52_report.json"),
            "--analysis-level",
            "full",
            "--sec-commit",
            "831c5301e4a829957117f47cfd7b388d99037a6a",
            "--kernel-source-commit",
            "a73978e16f87d704893e4b3a637be257420d43f3",
            "--author",
            "CIP Security Triage",
            "--id",
            "https://openvex.dev/docs/kernelvex/cip/v5.10.224-cip52/831c5301e4a8",
            "--timestamp",
            "2026-11-15T12:00:00+00:00",
            "--output",
            str(out_file),
        ]
    )
    assert exit_code == EXIT_OPEN_TRIAGE

    emitted = json.loads(out_file.read_text(encoding="utf-8"))
    golden = json.loads(
        (FIXTURES / "golden" / "openvex_full_cip.golden.json").read_text(encoding="utf-8")
    )
    assert emitted == golden

    # Validate default document against meta schema AND stripped document against upstream schema.
    validate_openvex_document(emitted, strict_openvex=False)
    stripped = {k: v for k, v in emitted.items() if k != "meta"}
    upstream_schema = json.loads(
        (REPO_ROOT / "schemas" / "openvex_v0.2.0.upstream.schema.json").read_text(encoding="utf-8")
    )
    Draft202012Validator(upstream_schema).validate(stripped)

    by_cve = {stmt["vulnerability"]["name"]: stmt for stmt in emitted["statements"]}
    assert by_cve["CVE-2024-40901"]["status"] == "not_affected"
    assert by_cve["CVE-2024-40901"]["justification"] == "vulnerable_code_not_present"
    assert (
        "check_introduced_by_file_compiled: no file is compiled"
        in by_cve["CVE-2024-40901"]["status_notes"]
    )
    assert by_cve["CVE-2024-40990"]["status"] == "fixed"
    assert by_cve["CVE-2024-44958"]["status"] == "under_investigation"


def test_strict_openvex_writes_sidecar_meta(tmp_path: Path) -> None:
    out_file = tmp_path / "strict.vex.json"
    exit_code = main(
        [
            "vex",
            "emit",
            "--strict-openvex",
            "--fail-on",
            "under_investigation",
            "--kernel-version",
            "v5.10.224-cip52",
            "--kernel-config",
            str(FIXTURES / "configs" / "5.10.y-cip_x86_cip_merged_defconfig"),
            "--report",
            str(FIXTURES / "reports" / "cve_triage_v5.10.224-cip52_report.json"),
            "--sec-commit",
            "831c5301e4a829957117f47cfd7b388d99037a6a",
            "--output",
            str(out_file),
        ]
    )
    assert exit_code == EXIT_POLICY_FAIL
    doc = json.loads(out_file.read_text(encoding="utf-8"))
    assert "meta" not in doc
    validate_openvex_document(doc, strict_openvex=True)
    sidecar = tmp_path / "strict.vex.json.meta.json"
    assert sidecar.is_file()
    assert json.loads(sidecar.read_text(encoding="utf-8"))["sec_commit"] == (
        "831c5301e4a829957117f47cfd7b388d99037a6a"
    )


def test_unexpected_failure_never_emits_not_affected_and_purl_fallback() -> None:
    kconfig = load_kconfig(FIXTURES / "configs" / "5.15.y_x86_cip_merged_defconfig")
    std_profile = resolve_profile("standard", "5.15.165", stable_branch="stable/5.15")

    # kernel.org URLs canonicalize cleanly to pkg:generic/kernel.org/linux@...
    purl = build_product_purl(
        kernel_url=std_profile.default_kernel_url,
        kernel_version="5.15.165",
        kernel_arch="x86_64",
        config_name=".config",
    )
    assert purl == "pkg:generic/kernel.org/linux@5.15.165?arch=x86_64&config=.config"

    # Generic remote SSH URLs flow through url2purl preserving download_url qualifier.
    internal_purl = build_product_purl(
        kernel_url="ssh://git.corp.internal/linux",
        kernel_version="5.15.165+dirty",
        kernel_arch="x86_64",
        config_name=".config",
    )
    assert internal_purl == (
        "pkg:generic/linux@5.15.165%2Bdirty?arch=x86_64&config=.config"
        "&download_url=ssh://git.corp.internal/linux"
    )
    # Non-URL identifiers where url2purl returns None fall back safely to kernel.org generic PURL.
    local_purl = build_product_purl(
        kernel_url="local-kernel-tree",
        kernel_version="5.15.165+dirty",
        kernel_arch="x86_64",
        config_name=".config",
    )
    assert local_purl == "pkg:generic/kernel.org/linux@5.15.165%2Bdirty?arch=x86_64&config=.config"
    dirty_profile = resolve_profile("standard", "5.15.165+dirty", stable_branch="stable/5.15")
    dirty_vex, _ = emit_openvex(
        report_payload=[
            json.loads(
                (FIXTURES / "reports" / "cve_triage_v5.10.224-cip52_report.json").read_text(
                    encoding="utf-8"
                )
            )[0]
        ],
        profile_cfg=dirty_profile,
        author="CI",
        kernel_arch="x86_64",
        config_name=".config",
        kernel_config_sha256=kconfig.raw_bytes_sha256,
        sec_commit="831c5301e4a829957117f47cfd7b388d99037a6a",
    )
    assert "/5.15.165%2Bdirty/" in dirty_vex["@id"]

    custom = build_product_purl(
        kernel_url=std_profile.default_kernel_url,
        kernel_version="5.15.165",
        kernel_arch="x86_64",
        config_name=".config",
        explicit_purl="pkg:yocto/poky/linux-yocto@5.15.165?machine=qemux86-64",
    )
    assert custom == "pkg:yocto/poky/linux-yocto@5.15.165?machine=qemux86-64"

    # Real CVE-2024-40901 with simulated kmax unexpected failure must yield under_investigation.
    raw_report = json.loads(
        (FIXTURES / "reports" / "cve_triage_v5.10.224-cip52_report.json").read_text(
            encoding="utf-8"
        )
    )
    failing_entry = {
        "cve": raw_report[0]["cve"],
        "check_results": [
            {"name": "check_ignore", "result": "relevant", "reason": "no ignore"},
            {"name": "check_introduced_by_file_compiled", "result": "unexpected failure"},
            {"name": "check_fixed_by", "result": "not relevant", "reason": "hypothetical"},
        ],
    }
    vex_doc, _ = emit_openvex(
        report_payload=[failing_entry],
        profile_cfg=std_profile,
        author="CI",
        kernel_arch="x86_64",
        config_name=".config",
        kernel_config_sha256=kconfig.raw_bytes_sha256,
        sec_commit="831c5301e4a829957117f47cfd7b388d99037a6a",
        analysis_level="full",
    )
    stmt = vex_doc["statements"][0]
    assert stmt["status"] == "under_investigation"
    assert "unexpected failure" in stmt["status_notes"]

    # Policy affected mode + exit codes 0 / 10 / 30 / 20
    vex_affected, _ = emit_openvex(
        report_payload=[raw_report[2]],
        profile_cfg=std_profile,
        author="CI",
        kernel_arch="x86_64",
        config_name=".config",
        kernel_config_sha256=kconfig.raw_bytes_sha256,
        sec_commit="831c5301e4a829957117f47cfd7b388d99037a6a",
        policy_affected=True,
    )
    assert vex_affected["statements"][0]["status"] == "affected"
    assert evaluate_policy_exit_code(vex_affected, fail_on="affected")[0] == EXIT_POLICY_FAIL
    assert evaluate_policy_exit_code(vex_affected, fail_on="none")[0] == EXIT_OPEN_TRIAGE

    vex_closed, _ = emit_openvex(
        report_payload=raw_report[:2],
        profile_cfg=std_profile,
        author="CI",
        kernel_arch="x86_64",
        config_name=".config",
        kernel_config_sha256=kconfig.raw_bytes_sha256,
        sec_commit="831c5301e4a829957117f47cfd7b388d99037a6a",
    )
    assert evaluate_policy_exit_code(vex_closed, fail_on="under_investigation")[0] == EXIT_OK

    # Tool errors map cleanly to exit code 20
    assert main(["analyze", "quick", "--kernel-version", "5.15.165"]) == EXIT_TOOL_ERROR
    with pytest.raises(KernelVexError):
        emit_openvex(
            report_payload=[],
            profile_cfg=std_profile,
            author="CI",
            kernel_arch="x86_64",
            config_name=".config",
            kernel_config_sha256=kconfig.raw_bytes_sha256,
            sec_commit="831c5301e4a829957117f47cfd7b388d99037a6a",
        )
