"""Unit tests for kernel version parsing, profile auto-detection, and branch scoping."""

from __future__ import annotations

import pytest

from kernelvex import KernelVexError
from kernelvex.profile import is_cve_applicable_to_profile, resolve_profile
from kernelvex.versions import parse_kernel_version


def test_version_ordering_handles_rc_cip_rt_and_stable() -> None:
    v_rc3 = parse_kernel_version("v6.10-rc3")
    v_rc5 = parse_kernel_version("v6.10-rc5")
    v_final = parse_kernel_version("6.10")
    v_610_5 = parse_kernel_version("6.10.5")

    assert v_rc3 < v_rc5 < v_final < v_610_5
    assert parse_kernel_version("v5.15.165") == parse_kernel_version("5.15.165")

    v_cip50 = parse_kernel_version("v5.10.221-cip50")
    v_cip52 = parse_kernel_version("v5.10.224-cip52")
    v_rt21 = parse_kernel_version("v5.10.223-cip51-rt21")
    assert v_cip50 < v_rt21 < v_cip52
    assert v_cip52.is_cip is True
    assert parse_kernel_version("6.1.0-28-amd64").series == (6, 1)


def test_invalid_versions_raise_kernelvex_error() -> None:
    for bad in ("", "   ", "not-a-version", "version:5.4.0-9.12"):
        with pytest.raises(KernelVexError):
            parse_kernel_version(bad)


def test_profile_autodetection_and_explicit_overrides() -> None:
    cip_auto = resolve_profile(None, "v5.10.224-cip52")
    assert cip_auto.profile == "cip"
    assert cip_auto.stable_branch == "cip/5.10"
    assert cip_auto.use_cip_flag is True

    cip_rt = resolve_profile("auto", "5.10.223-cip51-rt21")
    assert cip_rt.profile == "cip"
    assert cip_rt.stable_branch == "cip/5.10-rt"

    std_auto = resolve_profile("auto", "5.15.165")
    assert std_auto.profile == "standard"
    assert std_auto.stable_branch == "stable/5.15"
    assert std_auto.use_cip_flag is False

    # Section 6 CI example allows --profile cip combined with --stable-branch stable/5.15
    explicit_cip_on_stable = resolve_profile("cip", "5.15.165", stable_branch="stable/5.15")
    assert explicit_cip_on_stable.profile == "cip"
    assert explicit_cip_on_stable.stable_branch == "stable/5.15"
    assert explicit_cip_on_stable.use_cip_flag is True

    with pytest.raises(KernelVexError):
        resolve_profile("invalid", "5.15.165")

    with pytest.raises(KernelVexError):
        resolve_profile("standard", "5.15.165", stable_branch="   ")


def test_standard_profile_ignores_cip_only_entries() -> None:
    cip_only = {
        "name": "CVE-2024-40901",
        "introduced_by": {"cip/5.10": ["abc"]},
        "fixed_by": {"cip/5.10": ["def"]},
    }
    mixed = {
        "name": "CVE-2024-40901",
        "introduced_by": {"mainline": ["abc"]},
        "fixed_by": {"cip/5.10": ["def"], "stable/5.15": ["ghi"]},
    }
    assert is_cve_applicable_to_profile(cip_only, "cip") is True
    assert is_cve_applicable_to_profile(cip_only, "standard") is False
    assert is_cve_applicable_to_profile(mixed, "standard") is True
