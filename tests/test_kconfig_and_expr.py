"""Unit tests for .config / config.gz loading and Kmax boolean formula evaluation."""

from __future__ import annotations

import gzip
from pathlib import Path

import pytest

from kernelvex import KernelVexError
from kernelvex.kconfig import eval_kmax_config_expr, load_kconfig

FIXTURES = Path(__file__).resolve().parent / "fixtures"


def test_load_real_cip_defconfig_and_gzipped_config(tmp_path: Path) -> None:
    cfg_path = FIXTURES / "configs" / "5.10.y-cip_x86_cip_merged_defconfig"
    loaded = load_kconfig(cfg_path)

    assert loaded.detected_arch == "x86_64"
    assert loaded.make_arch == "x86"
    assert "CONFIG_SYSVIPC" in loaded.enabled_options
    assert "CONFIG_BTRFS_FS" in loaded.enabled_options  # =m module is enabled
    assert "CONFIG_SCSI_MPT3SAS" not in loaded.enabled_options
    assert "CONFIG_LOCALVERSION_AUTO" not in loaded.enabled_options
    assert len(loaded.raw_bytes_sha256) == 64

    # /proc/config.gz must yield identical options and uncompressed SHA-256
    gz_path = tmp_path / "config.gz"
    gz_path.write_bytes(gzip.compress(cfg_path.read_bytes()))
    loaded_gz = load_kconfig(gz_path)
    assert loaded_gz.enabled_options == loaded.enabled_options
    assert loaded_gz.raw_bytes_sha256 == loaded.raw_bytes_sha256


def test_load_kconfig_arm64_and_invalid_inputs(tmp_path: Path) -> None:
    arm_cfg = tmp_path / "arm64.config"
    arm_cfg.write_text("CONFIG_ARM64=y\n# CONFIG_FOO is not set\nCONFIG_BAR=n\n", encoding="utf-8")
    loaded = load_kconfig(arm_cfg)
    assert loaded.detected_arch == "aarch64"
    assert loaded.make_arch == "arm64"
    assert loaded.enabled_options == frozenset({"CONFIG_ARM64"})

    with pytest.raises(KernelVexError):
        load_kconfig(tmp_path / "missing.config")

    bad_gz = tmp_path / "broken.config.gz"
    bad_gz.write_bytes(b"\x1f\x8bnot-valid-gzip")
    with pytest.raises(KernelVexError):
        load_kconfig(bad_gz)


def test_eval_kmax_config_expr_precedence_and_errors() -> None:
    enabled = {"CONFIG_X86", "CONFIG_NET", "CONFIG_BTRFS_FS"}

    assert eval_kmax_config_expr("(CONFIG_X86 && CONFIG_NET)", enabled) is True
    assert eval_kmax_config_expr("(CONFIG_X86 && CONFIG_SCSI_MPT3SAS)", enabled) is False
    assert (
        eval_kmax_config_expr("((CONFIG_SCSI_MPT3SAS || CONFIG_BTRFS_FS) && CONFIG_X86)", enabled)
        is True
    )
    assert eval_kmax_config_expr("(!CONFIG_SCSI_MPT3SAS && True)", enabled) is True
    assert eval_kmax_config_expr("False || CONFIG_NET", enabled) is True

    for malformed in ("", "()", "CONFIG_NET &&", "CONFIG_NET CONFIG_X86", "unknown_token"):
        with pytest.raises(ValueError):
            eval_kmax_config_expr(malformed, enabled)
