"""Unit tests for in-process ``kernelvex.accel`` hooks and O(N) OpenVEX validation."""

from __future__ import annotations

import copy
import os
import pickle
import shutil
import subprocess
import sys
import time
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

from kernelvex import KernelVexError, accel
from kernelvex.catalog import refresh_catalog
from kernelvex.cli import _build_parser
from kernelvex.full import run_full_analysis
from kernelvex.kconfig import load_kconfig
from kernelvex.openvex import validate_openvex_document
from kernelvex.profile import resolve_profile

FIXTURES = Path(__file__).resolve().parent / "fixtures"


def _git(repo: Path, *args: str) -> str:
    """Run git cleanly in ``repo`` and return stripped stdout."""
    proc = subprocess.run(
        ["git", "-C", str(repo), *args],
        check=True,
        capture_output=True,
        text=True,
    )
    return proc.stdout.strip()


def _install_fake_upstream_modules(monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    """Register minimal fake ``cve_triage`` / ``kmax`` / ``z3`` modules in ``sys.modules``.

    Returns mutable call counters so tests can verify caching and pre-fork Z3 isolation.
    """
    counters: dict[str, Any] = {
        "unpickle_calls": 0,
        "z3_calls": 0,
        "z3_imported_by_from_file": False,
    }

    class HeaderSearchDepthException(Exception):
        pass

    class FakeGitNameStatus:
        """Minimal stand-in for ``cve_triage.triage.git.GitNameStatus``."""

        def __init__(self, added: list[str], renamed: list[tuple[str, str]]) -> None:
            self.added = added
            self.copied: list[str] = []
            self.renamed = renamed

        @classmethod
        def parse(cls, raw: str) -> FakeGitNameStatus:
            added: list[str] = []
            renamed: list[tuple[str, str]] = []
            for line in raw.splitlines()[1:]:
                if line.startswith("A"):
                    added.append(line.split("\t", 1)[1].strip())
                elif line.startswith("R"):
                    parts = line.split("\t")
                    renamed.append((parts[1].strip(), parts[2].strip()))
            return cls(added=added, renamed=renamed)

    class FakeBoolExpr:
        def __init__(self, expr: str) -> None:
            self.expr = expr

        @classmethod
        def parse(cls, text: str) -> tuple[FakeBoolExpr, str]:
            return cls(text.strip()), ""

        def __repr__(self) -> str:
            return f"FakeBoolExpr({self.expr!r})"

    class FakeKernelSource:
        def setup_repo(self, no_clone: bool, tempdir: Any) -> Path:
            del no_clone, tempdir
            return Path(".")

    class FakeCacheManager:
        def create_kmax_cache(
            self, version: Any, kmax_formulas: str | None, root: str = ".cache"
        ) -> Any:
            del self, version, kmax_formulas, root
            return type("FakeCache", (), {"exists": lambda _s: False})()

        def copy_cache(self, src: Path, dst: Path | None) -> None:
            del self, src, dst

    git_mod = ModuleType("cve_triage.triage.git")
    git_mod.MAX_HEADER_SEARCH_DEPTH = 30  # type: ignore[attr-defined]
    git_mod.HeaderSearchDepthException = HeaderSearchDepthException  # type: ignore[attr-defined]
    git_mod.GitNameStatus = FakeGitNameStatus  # type: ignore[attr-defined]
    git_mod.header_impacted_files = object()  # type: ignore[attr-defined]
    git_mod.track_file_at_revision = object()  # type: ignore[attr-defined]
    git_mod.changed_files_at_revision = object()  # type: ignore[attr-defined]

    kmax_triage_mod = ModuleType("cve_triage.triage.kmax")
    kmax_triage_mod.BoolExpression = FakeBoolExpr  # type: ignore[attr-defined]
    kmax_triage_mod.config_for_file = object()  # type: ignore[attr-defined]

    ks_mod = ModuleType("cve_triage.triage.kernel_source")
    ks_mod.KernelSource = FakeKernelSource  # type: ignore[attr-defined]

    cache_mod = ModuleType("cve_triage.triage.cache_manager")
    cache_mod.CacheManager = FakeCacheManager  # type: ignore[attr-defined]

    ib_mod = ModuleType("cve_triage.triage.checks.introduced_by")
    ib_mod.config_for_file = object()  # type: ignore[attr-defined]
    ib_mod.header_impacted_files = object()  # type: ignore[attr-defined]
    ib_mod.changed_files_at_revision = object()  # type: ignore[attr-defined]

    fb_mod = ModuleType("cve_triage.triage.checks.fixed_by")
    fb_mod.config_for_file = object()  # type: ignore[attr-defined]
    fb_mod.header_impacted_files = object()  # type: ignore[attr-defined]
    fb_mod.changed_files_at_revision = object()  # type: ignore[attr-defined]
    fb_mod.track_file_at_revision = object()  # type: ignore[attr-defined]

    kmax_common_mod = ModuleType("kmax.common")

    def _unpickle_kmax_file(path: str) -> dict[str, str]:
        counters["unpickle_calls"] += 1
        with open(path, "rb") as handle:
            return pickle.load(handle)

    def _get_kmax_constraints(formulas: dict[str, str], unit: str, view: bool = False) -> list[str]:
        del view
        return [formulas[unit]]

    kmax_common_mod.quiet = False  # type: ignore[attr-defined]
    kmax_common_mod.unpickle_kmax_file = _unpickle_kmax_file  # type: ignore[attr-defined]
    kmax_common_mod.get_kmax_constraints = _get_kmax_constraints  # type: ignore[attr-defined]

    z3_mod = ModuleType("z3")

    def _z3_bool_val(val: bool) -> str:
        return str(val)

    def _z3_and(a: str, b: str) -> str:
        return b if a == "True" else f"And({a}, {b})"

    def _z3_simplify(expr: str) -> str:
        counters["z3_calls"] += 1
        return expr

    z3_mod.BoolVal = _z3_bool_val  # type: ignore[attr-defined]
    z3_mod.And = _z3_and  # type: ignore[attr-defined]
    z3_mod.simplify = _z3_simplify  # type: ignore[attr-defined]

    pkg_specs = {
        "cve_triage": ModuleType("cve_triage"),
        "cve_triage.triage": ModuleType("cve_triage.triage"),
        "cve_triage.triage.checks": ModuleType("cve_triage.triage.checks"),
        "cve_triage.triage.git": git_mod,
        "cve_triage.triage.kmax": kmax_triage_mod,
        "cve_triage.triage.kernel_source": ks_mod,
        "cve_triage.triage.cache_manager": cache_mod,
        "cve_triage.triage.checks.introduced_by": ib_mod,
        "cve_triage.triage.checks.fixed_by": fb_mod,
        "kmax": ModuleType("kmax"),
        "kmax.common": kmax_common_mod,
        "z3": z3_mod,
    }
    for name, mod in pkg_specs.items():
        monkeypatch.setitem(sys.modules, name, mod)

    counters["mods"] = pkg_specs
    return counters


def test_include_graph_global_local_cycles_and_depth_limit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Verify single-pass include index parity across global, local, cycles, and depth > 30."""
    accel.clear_caches()
    counters = _install_fake_upstream_modules(monkeypatch)
    depth_exc = counters["mods"]["cve_triage.triage.git"].HeaderSearchDepthException

    repo = tmp_path / "linux"
    repo.mkdir()
    _git(repo, "init")
    _git(repo, "config", "user.name", "KernelVEX Test")
    _git(repo, "config", "user.email", "test@kernelvex.local")

    files = {
        "include/linux/sched.h": "#pragma once\n",
        "include/linux/mid.h": "#include <linux/sched.h>\n",
        "kernel/core.c": "#include <linux/mid.h>\n",
        "drivers/foo/local.h": "#pragma once\n",
        "drivers/foo/sub.h": '#include "local.h"\n',
        "drivers/foo/mod.c": '#include "sub.h"\n#include <linux/sched.h>\n',
        "drivers/foo/sub/child.c": '#include "../local.h"\n',
        "drivers/foo/sub/deep.h": "#pragma once\n",
        "drivers/foo/rel.c": '#include "sub/deep.h"\n',
        "drivers/bar/local.h": "#pragma once\n",
        "drivers/bar/other.c": '#include "local.h"\n',
        "include/linux/cyc_a.h": "#include <linux/cyc_b.h>\n",
        "include/linux/cyc_b.h": "#include <linux/cyc_a.h>\n",
        "kernel/cyc.c": "#include <linux/cyc_a.h>\n",
    }
    # Build a 33-header deep chain to verify MAX_HEADER_SEARCH_DEPTH == 30 raises cleanly.
    files["include/linux/d_00.h"] = "#pragma once\n"
    for idx in range(1, 33):
        files[f"include/linux/d_{idx:02d}.h"] = f"#include <linux/d_{idx - 1:02d}.h>\n"

    for rel, content in files.items():
        target = repo / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")

    _git(repo, "add", ".")
    _git(repo, "commit", "-q", "-m", "initial kernel tree")

    # Global transitive header lookup finds both direct and indirect .c includers.
    impacted_sched = set(
        accel.accelerated_header_impacted_files(str(repo), "include/linux/sched.h")
    )
    assert impacted_sched == {"drivers/foo/mod.c", "kernel/core.c"}

    # Local header scoping matches files under drivers/foo/ without bleeding into drivers/bar/
    # or bubbling upward outside drivers/foo/sub/.
    impacted_local = set(accel.accelerated_header_impacted_files(str(repo), "drivers/foo/local.h"))
    assert impacted_local == {"drivers/foo/mod.c", "drivers/foo/sub/child.c"}
    assert accel.accelerated_header_impacted_files(str(repo), "drivers/foo/sub/deep.h") == []

    # Cyclic includes terminate cleanly and return unique .c files.
    assert accel.accelerated_header_impacted_files(str(repo), "include/linux/cyc_a.h") == [
        "kernel/cyc.c"
    ]

    # Header chain deeper than MAX_HEADER_SEARCH_DEPTH raises HeaderSearchDepthException.
    with pytest.raises(depth_exc):
        accel.accelerated_header_impacted_files(str(repo), "include/linux/d_00.h")


def test_kmax_formula_index_prefork_safety_order_and_caching(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Verify pre-fork unpickle avoids z3, preserves pickle order, and caches post-fork solves."""
    accel.clear_caches()
    counters = _install_fake_upstream_modules(monkeypatch)

    kmax_path = tmp_path / "v7.2.kmax"
    # Insert out of alphabetical order to verify matching_units preserves original dict rank.
    raw_formulas = {
        "drivers/foo/bar.o.z": "CONFIG_Z",
        "drivers/foo/bar.o": "CONFIG_BAR",
        "kernel/sched/core.c.o": "True",
    }
    with kmax_path.open("wb") as handle:
        pickle.dump(raw_formulas, handle)

    # Temporarily block `import z3` while constructing pre-fork KmaxFormulaIndex.
    monkeypatch.setitem(sys.modules, "z3", None)
    idx = accel.get_or_load_kmax_index(kmax_path)
    assert idx.matching_units("drivers/foo/bar.o") == [
        "drivers/foo/bar.o.z",
        "drivers/foo/bar.o",
    ]
    assert counters["unpickle_calls"] == 1

    # Re-enable fake z3 module for post-fork worker evaluation.
    monkeypatch.setitem(sys.modules, "z3", counters["mods"]["z3"])

    expr1 = accel.accelerated_config_for_file(".", kmax_path, "kernel/sched/core.c.c")
    expr2 = accel.accelerated_config_for_file(".", kmax_path, "kernel/sched/core.c.o")
    assert expr1.expr == "True"
    assert expr2.expr == "True"
    # Fresh BoolExpression objects are returned, while Z3 simplify ran only once.
    assert expr1 is not expr2
    assert counters["z3_calls"] == 1

    # Missing compilation units raise ValueError and stay cached cleanly.
    with pytest.raises(ValueError, match="no kmax compile information"):
        accel.accelerated_config_for_file(".", kmax_path, "drivers/missing/nope.c")


def test_track_file_memoizes_merge_base_and_install_accelerators(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Verify merge-base/log memoization across files and idempotent module patching."""
    accel.clear_caches()
    counters = _install_fake_upstream_modules(monkeypatch)

    repo = tmp_path / "linux"
    repo.mkdir()
    _git(repo, "init")
    _git(repo, "config", "user.name", "KernelVEX Test")
    _git(repo, "config", "user.email", "test@kernelvex.local")

    (repo / "drivers/old").mkdir(parents=True)
    (repo / "drivers/old/a.c").write_text("int a = 1;\n// line2\n", encoding="utf-8")
    (repo / "drivers/old/b.c").write_text("int b = 1;\n// line2\n", encoding="utf-8")
    _git(repo, "add", ".")
    _git(repo, "commit", "-q", "-m", "base target rev")
    target_rev = _git(repo, "rev-parse", "HEAD")

    (repo / "drivers/new").mkdir(parents=True)
    _git(repo, "mv", "drivers/old/a.c", "drivers/new/a.c")
    _git(repo, "mv", "drivers/old/b.c", "drivers/new/b.c")
    (repo / "drivers/new/later.c").write_text("int later = 1;\n", encoding="utf-8")
    _git(repo, "add", ".")
    _git(repo, "commit", "-q", "-m", "rename a/b and add later")
    fix_rev = _git(repo, "rev-parse", "HEAD")

    real_run = subprocess.run
    merge_base_calls = 0

    def _spy_run(cmd: list[str], *args: Any, **kwargs: Any) -> subprocess.CompletedProcess[Any]:
        nonlocal merge_base_calls
        if "merge-base" in cmd:
            merge_base_calls += 1
        return real_run(cmd, *args, **kwargs)

    monkeypatch.setattr(accel.subprocess, "run", _spy_run)

    # Track three files from the same (fix_rev, target_rev) pair: merge-base runs once.
    assert (
        accel.accelerated_track_file_at_revision(str(repo), fix_rev, target_rev, "drivers/new/a.c")
        == "drivers/old/a.c"
    )
    assert (
        accel.accelerated_track_file_at_revision(str(repo), fix_rev, target_rev, "drivers/new/b.c")
        == "drivers/old/b.c"
    )
    assert (
        accel.accelerated_track_file_at_revision(
            str(repo), fix_rev, target_rev, "drivers/new/later.c"
        )
        is None
    )
    assert merge_base_calls == 1
    assert set(accel.accelerated_changed_files_at_revision(str(repo), fix_rev)) == {
        "drivers/new/a.c",
        "drivers/new/b.c",
        "drivers/new/later.c",
    }

    # install_accelerators updates both defining modules and checks/ import bindings cleanly.
    accel.install_accelerators()
    accel.install_accelerators()
    mods = counters["mods"]
    assert mods["cve_triage.triage.kmax"].config_for_file is accel.accelerated_config_for_file
    assert (
        mods["cve_triage.triage.checks.introduced_by"].config_for_file
        is accel.accelerated_config_for_file
    )
    assert (
        mods["cve_triage.triage.checks.fixed_by"].track_file_at_revision
        is accel.accelerated_track_file_at_revision
    )
    assert (
        mods["cve_triage.triage.checks.introduced_by"].header_impacted_files
        is accel.accelerated_header_impacted_files
    )


def test_cli_no_accel_flag_and_runner_dispatch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Verify ``--no-accel`` parsing and accelerated vs fallback invocation in ``full.py``."""
    parser = _build_parser()
    full_args = parser.parse_args(
        [
            "analyze",
            "full",
            "--kernel-version",
            "5.15.165",
            "--kernel-config",
            ".config",
            "--kernel-source",
            "src",
            "--no-accel",
        ]
    )
    assert full_args.no_accel is True

    pipe_args = parser.parse_args(
        [
            "ci",
            "pipeline",
            "--kernel-version",
            "5.15.165",
            "--kernel-config",
            ".config",
            "--kernel-source",
            "src",
            "--mode",
            "full",
        ]
    )
    assert pipe_args.no_accel is False

    # Prepare cached catalog from fixture sec repo and kernel repo with annotated v5.15.165 tag.
    cache_dir = tmp_path / "cache"
    sec_src = tmp_path / "sec-src"
    shutil.copytree(FIXTURES / "sec", sec_src)
    _git(sec_src, "init", "-b", "master")
    _git(sec_src, "config", "user.name", "KernelVEX Test")
    _git(sec_src, "config", "user.email", "test@kernelvex.local")
    _git(sec_src, "add", ".")
    _git(sec_src, "commit", "-q", "-m", "sec commit")
    refresh_catalog(cache_dir=cache_dir, sec_url=str(sec_src), sec_ref="master")

    ksrc = tmp_path / "linux"
    ksrc.mkdir()
    _git(ksrc, "init")
    _git(ksrc, "config", "user.name", "KernelVEX Test")
    _git(ksrc, "config", "user.email", "test@kernelvex.local")
    (ksrc / "Makefile").write_text("VERSION = 5\n", encoding="utf-8")
    _git(ksrc, "add", ".")
    _git(ksrc, "commit", "-q", "-m", "init")
    _git(ksrc, "tag", "-a", "v5.15.165", "-m", "v5.15.165")

    kconfig = load_kconfig(FIXTURES / "configs" / "5.15.y_x86_cip_merged_defconfig")
    profile_cfg = resolve_profile("standard", "5.15.165", stable_branch="stable/5.15")

    invoked_cmds: list[list[str]] = []
    real_run = subprocess.run

    def _fake_subprocess_run(cmd: list[str], **kwargs: Any) -> subprocess.CompletedProcess[Any]:
        if cmd[0] == "git":
            return real_run(cmd, **kwargs)
        invoked_cmds.append(cmd)
        if "--out" in cmd:
            out_file = Path(cmd[cmd.index("--out") + 1])
            out_file.write_text('[{"cve": {"name": "CVE-2024-40901"}}]', encoding="utf-8")
        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

    monkeypatch.setattr("kernelvex.full._can_use_inprocess_accel", lambda: True)
    monkeypatch.setattr("kernelvex.full.subprocess.run", _fake_subprocess_run)

    # Default run uses python -m kernelvex.accel triage and records accel_enabled=True.
    env_accel = run_full_analysis(
        cache_dir=cache_dir,
        kernel_source=ksrc,
        kconfig=kconfig,
        profile_cfg=profile_cfg,
        jobs=2,
        no_accel=False,
    )
    assert env_accel["meta"]["accel_enabled"] is True
    assert any(
        cmd[:4] == [sys.executable, "-m", "kernelvex.accel", "triage"] for cmd in invoked_cmds
    )

    # With --no-accel=True, falls back cleanly to raw cve-triage binary and accel_enabled=False.
    invoked_cmds.clear()
    fake_bin = tmp_path / "cve-triage"
    fake_bin.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    fake_bin.chmod(0o755)
    monkeypatch.setenv("PATH", str(tmp_path), prepend=os.pathsep)

    env_plain = run_full_analysis(
        cache_dir=cache_dir,
        kernel_source=ksrc,
        kconfig=kconfig,
        profile_cfg=profile_cfg,
        jobs=2,
        no_accel=True,
    )
    assert env_plain["meta"]["accel_enabled"] is False
    assert any(cmd[:2] == [str(fake_bin), "triage"] for cmd in invoked_cmds)


def test_fast_openvex_validation_uniqueness_and_scale() -> None:
    """Verify O(N) OpenVEX validator rejects duplicates and scales cleanly to 4,000 items."""
    golden_path = FIXTURES / "golden" / "openvex_full_cip.golden.json"
    import json

    base_doc = json.loads(golden_path.read_text(encoding="utf-8"))
    validate_openvex_document(base_doc, strict_openvex=False)

    # Duplicate statement must still fail schema validation via full_validator fallback.
    dup_doc = copy.deepcopy(base_doc)
    dup_doc["statements"].append(copy.deepcopy(dup_doc["statements"][0]))
    with pytest.raises(KernelVexError, match="OpenVEX schema validation failed at statements"):
        validate_openvex_document(dup_doc, strict_openvex=False)

    # 4,000 unique statements must validate well under 2.0 seconds in both modes.
    template = copy.deepcopy(base_doc["statements"][0])
    large_statements = []
    for idx in range(4000):
        stmt = copy.deepcopy(template)
        stmt["vulnerability"] = {
            **stmt["vulnerability"],
            "name": f"CVE-2026-{10000 + idx}",
        }
        large_statements.append(stmt)

    large_meta_doc = {**base_doc, "statements": large_statements}
    t0 = time.monotonic()
    validate_openvex_document(large_meta_doc, strict_openvex=False)
    elapsed_meta = time.monotonic() - t0
    assert elapsed_meta < 2.0, f"Meta schema validation too slow: {elapsed_meta:.3f}s"

    large_strict_doc = {k: v for k, v in large_meta_doc.items() if k != "meta"}
    t1 = time.monotonic()
    validate_openvex_document(large_strict_doc, strict_openvex=True)
    elapsed_strict = time.monotonic() - t1
    assert elapsed_strict < 2.0, f"Strict schema validation too slow: {elapsed_strict:.3f}s"
