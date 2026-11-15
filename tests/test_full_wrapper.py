"""Tests for full-mode subprocess orchestration around cve-triage and kmax cache."""

from __future__ import annotations

import gzip
import json
import shutil
import stat
import subprocess
from pathlib import Path

import pytest

from kernelvex import EXIT_OK, EXIT_OPEN_TRIAGE, KernelVexError
from kernelvex.catalog import refresh_catalog
from kernelvex.cli import main
from kernelvex.full import (
    _configure_kbuild_env,
    resolve_kmax_cache_file,
    run_enrich_wrapper,
    run_full_analysis,
)
from kernelvex.kconfig import load_kconfig
from kernelvex.openvex import validate_openvex_document
from kernelvex.profile import resolve_profile

FIXTURES = Path(__file__).resolve().parent / "fixtures"


def _create_git_repo_with_tag(repo: Path, tag: str) -> str:
    """Create a tiny local kernel git repo with tag and return full commit SHA."""
    repo.mkdir(parents=True, exist_ok=True)
    (repo / "Makefile").write_text("VERSION = 5\nPATCHLEVEL = 10\n", encoding="utf-8")
    subprocess.run(["git", "init", "-b", "main", str(repo)], check=True, capture_output=True)
    subprocess.run(
        ["git", "-C", str(repo), "config", "user.email", "ci@example.org"],
        check=True,
        capture_output=True,
    )
    subprocess.run(
        ["git", "-C", str(repo), "config", "user.name", "CI"],
        check=True,
        capture_output=True,
    )
    subprocess.run(["git", "-C", str(repo), "add", "."], check=True, capture_output=True)
    subprocess.run(
        ["git", "-C", str(repo), "commit", "-m", "init"], check=True, capture_output=True
    )
    # Create an annotated tag because cve-triage runs `git describe --abbrev=0` without --tags.
    subprocess.run(
        ["git", "-C", str(repo), "tag", "-a", tag, "-m", tag], check=True, capture_output=True
    )
    sha = subprocess.check_output(["git", "-C", str(repo), "rev-parse", "HEAD"], text=True).strip()
    return sha


def _write_cli_stub(path: Path, capture_file: Path, report_source: Path | None = None) -> Path:
    """Create an executable script recording exact argv passed to cve-triage."""
    report_copy_stmt = (
        f"Path({str(report_source)!r}).read_text(encoding='utf-8')"
        if report_source is not None
        else "'[]'"
    )
    script = (
        "#!/usr/bin/env python3\n"
        "import json, sys\n"
        "from pathlib import Path\n"
        f"Path({str(capture_file)!r}).write_text(json.dumps(sys.argv[1:]), encoding='utf-8')\n"
        "argv = sys.argv[1:]\n"
        "if argv and argv[0] == 'triage':\n"
        "    out_idx = argv.index('--out') + 1\n"
        "    kmax_idx = argv.index('--kmax-formulas') + 1\n"
        "    Path(argv[kmax_idx]).write_text('kmax-formula-cache', encoding='utf-8')\n"
        f"    Path(argv[out_idx]).write_text({report_copy_stmt}, encoding='utf-8')\n"
    )
    path.write_text(script, encoding="utf-8")
    path.chmod(path.stat().st_mode | stat.S_IXUSR)
    return path


def _setup_sec_cache(tmp_path: Path) -> Path:
    sec_src = tmp_path / "sec-src"
    shutil.copytree(FIXTURES / "sec", sec_src)
    subprocess.run(["git", "init", "-b", "master", str(sec_src)], check=True, capture_output=True)
    subprocess.run(
        ["git", "-C", str(sec_src), "config", "user.email", "ci@example.org"],
        check=True,
        capture_output=True,
    )
    subprocess.run(
        ["git", "-C", str(sec_src), "config", "user.name", "CI"],
        check=True,
        capture_output=True,
    )
    subprocess.run(["git", "-C", str(sec_src), "add", "."], check=True, capture_output=True)
    subprocess.run(
        ["git", "-C", str(sec_src), "commit", "-m", "snapshot"], check=True, capture_output=True
    )
    cache_dir = tmp_path / "cache"
    refresh_catalog(cache_dir=cache_dir, sec_url=str(sec_src), sec_ref="master")
    return cache_dir


def test_full_analysis_cip_vs_standard_flags_and_kmax_file_cache(tmp_path: Path) -> None:
    cache_dir = _setup_sec_cache(tmp_path)
    cip_repo = tmp_path / "linux-cip"
    cip_sha = _create_git_repo_with_tag(cip_repo, "v5.10.224-cip52")

    # Test gzipped config decompression and isolated worktree path
    cfg_src = FIXTURES / "configs" / "5.10.y-cip_x86_cip_merged_defconfig"
    cfg_gz = tmp_path / "proc-config.gz"
    cfg_gz.write_bytes(gzip.compress(cfg_src.read_bytes()))
    kconfig = load_kconfig(cfg_gz)

    capture_json = tmp_path / "captured_argv.json"
    stub = _write_cli_stub(
        tmp_path / "cve-triage",
        capture_json,
        FIXTURES / "reports" / "cve_triage_v5.10.224-cip52_report.json",
    )

    cip_profile = resolve_profile("cip", "v5.10.224-cip52")
    env_cold = run_full_analysis(
        cache_dir=cache_dir,
        kernel_source=cip_repo,
        kconfig=kconfig,
        profile_cfg=cip_profile,
        cve_ids=["CVE-2024-40901", "CVE-2024-40990"],
        jobs=4,
        cve_triage_bin=str(stub),
    )
    argv_cip = json.loads(capture_json.read_text(encoding="utf-8"))
    assert argv_cip[0] == "triage"
    assert "--cip" in argv_cip
    assert "--no-clone" in argv_cip
    kmax_arg = Path(argv_cip[argv_cip.index("--kmax-formulas") + 1])
    assert kmax_arg.suffix == ".kmax"
    assert kmax_arg.is_file()
    assert env_cold["meta"]["kernel_source_commit"] == cip_sha
    assert env_cold["meta"]["kmax_cache_hit"] is False
    # Input config passed to cve-triage is decompressed plain text outside git repo
    cfg_arg = Path(argv_cip[argv_cip.index("--config") + 1])
    assert cfg_arg.name == "input.config"

    # Second run reuses persisted .kmax file -> kmax_cache_hit True
    env_warm = run_full_analysis(
        cache_dir=cache_dir,
        kernel_source=cip_repo,
        kconfig=kconfig,
        profile_cfg=cip_profile,
        cve_ids=["CVE-2024-40901", "CVE-2024-40990"],
        cve_triage_bin=str(stub),
    )
    assert env_warm["meta"]["kmax_cache_hit"] is True

    # Standard profile must NOT pass --cip to cve-triage
    std_repo = tmp_path / "linux-stable"
    _create_git_repo_with_tag(std_repo, "v5.15.165")
    std_profile = resolve_profile("standard", "5.15.165")
    run_full_analysis(
        cache_dir=cache_dir,
        kernel_source=std_repo,
        kconfig=kconfig,
        profile_cfg=std_profile,
        cve_ids=["CVE-2024-40901"],
        cve_triage_bin=str(stub),
    )
    argv_std = json.loads(capture_json.read_text(encoding="utf-8"))
    assert "--cip" not in argv_std

    # Enrich wrapper checks
    enriched_out = run_enrich_wrapper(
        cache_dir=cache_dir,
        kernel_source=cip_repo,
        versions=["v5.10"],
        out_dir=tmp_path / "enriched",
        cip=True,
        cve_ids=["CVE-2024-40901"],
        cve_triage_bin=str(stub),
    )
    assert enriched_out.is_dir()
    argv_enrich = json.loads(capture_json.read_text(encoding="utf-8"))
    assert argv_enrich[0] == "enrich"
    assert "--cip" in argv_enrich


def test_full_analysis_rejects_directory_kmax_cache_and_missing_tags(tmp_path: Path) -> None:
    existing_dir = tmp_path / "kmax_dir"
    existing_dir.mkdir()
    with pytest.raises(KernelVexError):
        resolve_kmax_cache_file(tmp_path, "cip", "a" * 40, "x86_64", existing_dir)

    # Repo without git tags must fail cleanly with KernelVexError (exit 20)
    untagged_repo = tmp_path / "untagged"
    untagged_repo.mkdir()
    (untagged_repo / "README").write_text("x", encoding="utf-8")
    subprocess.run(["git", "init", str(untagged_repo)], check=True, capture_output=True)
    subprocess.run(
        ["git", "-C", str(untagged_repo), "config", "user.email", "ci@example.org"],
        check=True,
        capture_output=True,
    )
    subprocess.run(
        ["git", "-C", str(untagged_repo), "config", "user.name", "CI"],
        check=True,
        capture_output=True,
    )
    subprocess.run(["git", "-C", str(untagged_repo), "add", "."], check=True, capture_output=True)
    subprocess.run(
        ["git", "-C", str(untagged_repo), "commit", "-m", "no tag"],
        check=True,
        capture_output=True,
    )

    cache_dir = _setup_sec_cache(tmp_path)
    kconfig = load_kconfig(FIXTURES / "configs" / "5.10.y-cip_x86_cip_merged_defconfig")
    stub = _write_cli_stub(tmp_path / "cve-triage", tmp_path / "cap.json")
    with pytest.raises(KernelVexError, match="missing git tags"):
        run_full_analysis(
            cache_dir=cache_dir,
            kernel_source=untagged_repo,
            kconfig=kconfig,
            profile_cfg=resolve_profile("cip", "v5.10.224-cip52"),
            cve_ids=["CVE-2024-40901"],
            cve_triage_bin=str(stub),
        )


def test_full_cli_commands_and_readonly_shared_clone_fallback(tmp_path: Path) -> None:
    """Exercise CLI subcommands end-to-end plus read-only source shared-clone fallback."""
    cache_dir = _setup_sec_cache(tmp_path)
    cip_repo = tmp_path / "linux-cip"
    cip_sha = _create_git_repo_with_tag(cip_repo, "v5.10.224-cip52")

    capture_json = tmp_path / "cli_captured_argv.json"
    report_fixture = FIXTURES / "reports" / "cve_triage_v5.10.224-cip52_report.json"
    stub = _write_cli_stub(tmp_path / "cve-triage", capture_json, report_fixture)
    cfg_path = FIXTURES / "configs" / "5.10.y-cip_x86_cip_merged_defconfig"

    # CLI: analyze quick
    quick_out = tmp_path / "out" / "quick.json"
    assert (
        main(
            [
                "--cache-dir",
                str(cache_dir),
                "analyze",
                "quick",
                "--kernel-version",
                "v5.10.224-cip52",
                "--kernel-config",
                str(cfg_path),
                "--cve-id",
                "CVE-2024-40990",
                "--output",
                str(quick_out),
            ]
        )
        == EXIT_OK
    )
    assert json.loads(quick_out.read_text(encoding="utf-8"))["meta"]["analysis_level"] == "quick"

    # CLI: enrich + catalog merge-enrich
    enriched_dir = tmp_path / "cli-enriched"
    assert (
        main(
            [
                "--cache-dir",
                str(cache_dir),
                "enrich",
                "--kernel-source",
                str(cip_repo),
                "--versions",
                "v5.10",
                "--out-dir",
                str(enriched_dir),
                "--cve-id",
                "CVE-2024-40901",
                "--cve-triage-bin",
                str(stub),
            ]
        )
        == EXIT_OK
    )
    (enriched_dir / "CVE-2024-40901.yml").write_text(
        "name: CVE-2024-40901\naffected-configs:\n  v5.10.224-cip52:\n  - (CONFIG_SCSI_MPT3SAS)\n",
        encoding="utf-8",
    )
    assert (
        main(
            [
                "--cache-dir",
                str(cache_dir),
                "catalog",
                "merge-enrich",
                "--enriched-dir",
                str(enriched_dir),
            ]
        )
        == EXIT_OK
    )

    # CLI: analyze full with --raw-report-out and read-only .git forcing clone --shared fallback
    full_out = tmp_path / "out" / "full.json"
    raw_out = tmp_path / "out" / "raw.json"
    git_dir = cip_repo / ".git"
    orig_mode = git_dir.stat().st_mode
    try:
        git_dir.chmod(stat.S_IRUSR | stat.S_IXUSR)
        rc_full = main(
            [
                "--log-format",
                "text",
                "--cache-dir",
                str(cache_dir),
                "analyze",
                "full",
                "--kernel-version",
                "v5.10.224-cip52",
                "--kernel-config",
                str(cfg_path),
                "--kernel-source",
                str(cip_repo),
                "--cve-id",
                "CVE-2024-40901",
                "CVE-2024-40990",
                "--cve-triage-bin",
                str(stub),
                "--raw-report-out",
                str(raw_out),
                "--output",
                str(full_out),
            ]
        )
        assert rc_full == EXIT_OK
    finally:
        git_dir.chmod(orig_mode)

    full_env = json.loads(full_out.read_text(encoding="utf-8"))
    assert full_env["meta"]["kernel_source_commit"] == cip_sha
    assert isinstance(json.loads(raw_out.read_text(encoding="utf-8")), list)

    # CLI: ci pipeline --mode full --report-out (reusing cached kmax formulas)
    vex_out = tmp_path / "out" / "pipeline.vex.json"
    pipe_report = tmp_path / "out" / "pipeline-report.json"
    rc_pipe = main(
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
            str(cfg_path),
            "--kernel-source",
            str(cip_repo),
            "--mode",
            "full",
            "--cve-id",
            "CVE-2024-40901",
            "CVE-2024-40990",
            "--cve-triage-bin",
            str(stub),
            "--report-out",
            str(pipe_report),
            "--output",
            str(vex_out),
        ]
    )
    assert rc_pipe == EXIT_OPEN_TRIAGE
    vex_doc = json.loads(vex_out.read_text(encoding="utf-8"))
    validate_openvex_document(vex_doc, strict_openvex=False)
    assert pipe_report.is_file()

    # Empty CVE filter selection must fail closed (KernelVexError) without calling cve-triage,
    # avoiding silent empty OpenVEX generation on mistyped CI year/profile filters.
    capture_json.unlink(missing_ok=True)
    with pytest.raises(KernelVexError, match="No applicable CVEs matched filters"):
        run_full_analysis(
            cache_dir=cache_dir,
            kernel_source=cip_repo,
            kconfig=load_kconfig(cfg_path),
            profile_cfg=resolve_profile("cip", "v5.10.224-cip52"),
            since_year=2030,
            cve_triage_bin=str(stub),
        )
    assert not capture_json.exists()

    with pytest.raises(KernelVexError, match="No applicable CVEs matched filters"):
        run_enrich_wrapper(
            cache_dir=cache_dir,
            kernel_source=cip_repo,
            versions=["v5.10"],
            out_dir=tmp_path / "empty-enriched",
            since_year=2030,
            cve_triage_bin=str(stub),
        )
    assert not capture_json.exists()


def test_configure_kbuild_env_cross_arch_and_overrides(monkeypatch: pytest.MonkeyPatch) -> None:
    """Verify native, explicit override, GNU cross-prefix, and LLVM=1 Kbuild env selection."""
    # Native architecture does not inject CROSS_COMPILE or LLVM.
    monkeypatch.setattr("kernelvex.full.platform.machine", lambda: "x86_64")
    monkeypatch.setattr("kernelvex.full.shutil.which", lambda cmd: None)
    env_native = _configure_kbuild_env({"PATH": "/usr/bin"}, "x86")
    assert env_native["ARCH"] == "x86"
    assert "CROSS_COMPILE" not in env_native
    assert "LLVM" not in env_native

    # Foreign architecture selects GNU CROSS_COMPILE prefix when matching gcc is present.
    monkeypatch.setattr("kernelvex.full.platform.machine", lambda: "aarch64")
    monkeypatch.setattr(
        "kernelvex.full.shutil.which",
        lambda cmd: "/usr/bin/x86_64-linux-gnu-gcc" if cmd == "x86_64-linux-gnu-gcc" else None,
    )
    env_cross_gcc = _configure_kbuild_env({}, "x86")
    assert env_cross_gcc["ARCH"] == "x86"
    assert env_cross_gcc["CROSS_COMPILE"] == "x86_64-linux-gnu-"
    assert "LLVM" not in env_cross_gcc

    # Foreign architecture falls back to LLVM=1 when cross-gcc is absent but clang+ld.lld exist.
    monkeypatch.setattr(
        "kernelvex.full.shutil.which",
        lambda cmd: f"/usr/bin/{cmd}" if cmd in {"clang", "ld.lld"} else None,
    )
    env_llvm = _configure_kbuild_env({}, "riscv")
    assert env_llvm["ARCH"] == "riscv"
    assert env_llvm["LLVM"] == "1"

    # Explicit caller overrides are always preserved intact.
    env_override = _configure_kbuild_env(
        {"ARCH": "arm64", "CROSS_COMPILE": "custom-gnu-", "LLVM": "0"}, "x86"
    )
    assert env_override["ARCH"] == "arm64"
    assert env_override["CROSS_COMPILE"] == "custom-gnu-"
    assert env_override["LLVM"] == "0"
