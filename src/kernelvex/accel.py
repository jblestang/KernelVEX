"""In-process accelerator hooks for upstream ``kernel-cve-triage`` and ``kmax``.

Replaces repeated per-CVE subprocess launches inside ``cve-triage triage``
workers with pre-fork indexed lookups and per-worker memoization while keeping
pinned upstream packages untouched in the environment:

1. ``KmaxFormulaIndex`` unpickles ``.kmax`` SMT2 strings once in the parent
   process before ``multiprocessing.Pool`` forks (Linux CoW shared, zero Z3
   state before ``fork()``) and evaluates ``z3.simplify`` lazily inside each
   worker with an in-memory cache (replacing thousands of ``kreader`` spawns).
2. ``IncludeGraphIndex`` builds a complete ``#include <...>`` and
   ``#include "..."`` reverse index via a single ``git grep`` scan before
   ``fork()`` (replacing hundreds of recursive ``git grep`` invocations).
3. Memoized ``_cached_merge_base``, ``track_file_at_revision``, and
   ``changed_files_at_revision`` eliminate redundant Git history traversals
   across commits and files inside each triage worker.
"""

from __future__ import annotations

import bisect
import functools
import logging
import pathlib
import subprocess
from collections import defaultdict
from typing import Any

# Upstream modules are optional outside the full container image; imported on demand
# so local unit tests can inject module stubs cleanly via sys.modules.
_LOGGER = logging.getLogger(__name__)

# Process-wide pre-fork read-only indices shared across workers via CoW.
_KMAX_INDICES: dict[str, KmaxFormulaIndex] = {}
_INCLUDE_INDICES: dict[str, IncludeGraphIndex] = {}

# Worker-local caches populated lazily strictly AFTER multiprocessing fork().
_EXPR_STRING_CACHE: dict[tuple[str, str], str | None] = {}
_MERGE_BASE_CACHE: dict[tuple[str, str, str], tuple[bool, str]] = {}
_TRACK_FILE_CACHE: dict[tuple[str, str, str, str], tuple[bool, str | None]] = {}
_CHANGED_FILES_CACHE: dict[tuple[str, str], tuple[str, ...]] = {}


def clear_caches() -> None:
    """Reset all pre-fork indices and worker-local memoization caches.

    Intended primarily for unit tests and isolated benchmarks so successive
    in-process invocations start from a clean state.
    """
    # Clear each module-level mapping in-place so existing aliases stay valid.
    _KMAX_INDICES.clear()
    _INCLUDE_INDICES.clear()
    _EXPR_STRING_CACHE.clear()
    _MERGE_BASE_CACHE.clear()
    _TRACK_FILE_CACHE.clear()
    _CHANGED_FILES_CACHE.clear()


def _normalize_repo_key(repo: str | pathlib.Path) -> str:
    """Canonicalize repository directory path for stable cache keying."""
    return str(pathlib.Path(repo).resolve())


def _normalize_obj_path(path: str | pathlib.Path) -> pathlib.Path:
    """Normalize a source or object path to its ``.o`` compilation unit name."""
    # Mirrors cve_triage.triage.kmax.config_for_file `.o` stem normalization.
    obj_path = pathlib.Path(path)
    if obj_path.suffix != ".o":
        obj_path = obj_path.parent / f"{obj_path.stem}.o"
    return obj_path


class KmaxFormulaIndex:
    """Sorted prefix index over pickled ``.kmax`` SMT2 formula strings.

    Attributes:
        path_key: Canonical filesystem path string of the backing ``.kmax`` file.
        formulas: Raw ``{unit: smt2_formula}`` dictionary in original pickle order.
        sorted_keys: Lexicographically sorted compilation unit keys for ``bisect``.
        ranks: Original pickle insertion rank per unit key to preserve ``kreader``
            multi-match output ordering without linear scans.
    """

    def __init__(self, path_key: str, formulas: dict[str, str]) -> None:
        """Build sorted bisect index and preserve insertion order ranks."""
        self.path_key = path_key
        self.formulas = formulas
        # Preserve original dict order via ranks while indexing sorted keys for bisect.
        self.ranks: dict[str, int] = {key: idx for idx, key in enumerate(formulas)}
        self.sorted_keys: list[str] = sorted(formulas)

    @classmethod
    def from_file(cls, kmax_file: str | pathlib.Path) -> KmaxFormulaIndex:
        """Unpickle SMT2 formulas from disk without initializing Z3 state.

        Args:
            kmax_file: Path to a pickled ``.kmax`` formula dictionary.

        Returns:
            Populated ``KmaxFormulaIndex`` safe to share across ``fork()``.
        """
        from kmax.common import unpickle_kmax_file

        # Resolve canonical path so Path and str callers hit the same CoW index.
        resolved = str(pathlib.Path(kmax_file).resolve())
        formulas = unpickle_kmax_file(resolved)
        return cls(path_key=resolved, formulas=formulas)

    def matching_units(self, prefix: str) -> list[str]:
        """Return all unit keys starting with ``prefix`` in original pickle order.

        Args:
            prefix: Target compilation unit prefix (typically ending in ``.o``).

        Returns:
            Matching unit keys ordered identically to ``kreader`` iteration.
        """
        # Sorted prefix scan avoids iterating all ~20k units on every CVE query.
        pos = bisect.bisect_left(self.sorted_keys, prefix)
        matches: list[str] = []
        while pos < len(self.sorted_keys) and self.sorted_keys[pos].startswith(prefix):
            matches.append(self.sorted_keys[pos])
            pos += 1
        # Most .o queries yield 0 or 1 match; preserve original dict order if multiple.
        if len(matches) > 1:
            matches.sort(key=self.ranks.__getitem__)
        return matches


def get_or_load_kmax_index(kmax_file: str | pathlib.Path) -> KmaxFormulaIndex:
    """Return a cached ``KmaxFormulaIndex`` or unpickle ``kmax_file`` once.

    Args:
        kmax_file: Path to the ``.kmax`` pickle archive.

    Returns:
        Cached or newly loaded ``KmaxFormulaIndex`` instance.
    """
    key = str(pathlib.Path(kmax_file).resolve())
    index = _KMAX_INDICES.get(key)
    if index is None:
        index = KmaxFormulaIndex.from_file(key)
        _KMAX_INDICES[key] = index
    return index


def accelerated_config_for_file(repo: str, kmax: str | pathlib.Path, path: str) -> Any:
    """In-process replacement for ``cve_triage.triage.kmax.config_for_file``.

    Must execute Z3 constraint parsing and simplification lazily on cache miss so
    parent processes never initialize Z3 globals before ``fork()``.

    Args:
        repo: Kernel repository path (unused, preserved for signature parity).
        kmax: Path to the ``.kmax`` pickle file.
        path: Kernel source or object path whose Kconfig condition is requested.

    Returns:
        Parsed ``cve_triage.triage.kmax.BoolExpression`` matching ``kreader``.

    Raises:
        ValueError: When no compilation unit in ``kmax`` matches ``path``.
    """
    del repo
    import kmax.common as kmax_common
    import z3
    from cve_triage.triage.kmax import BoolExpression

    obj_str = str(_normalize_obj_path(path))
    index = get_or_load_kmax_index(kmax)
    cache_key = (index.path_key, obj_str)

    # Check worker-local serialized expression cache before invoking Z3.
    if cache_key in _EXPR_STRING_CACHE:
        cached_out = _EXPR_STRING_CACHE[cache_key]
        if not cached_out:
            raise ValueError(f"no kmax compile information for '{obj_str}'")
        bool_expr, _ = BoolExpression.parse(" ".join(cached_out.split(" ")[1:]))
        return bool_expr

    units = index.matching_units(obj_str)
    if not units:
        # Memoize misses too so non-built paths skip repeat bisect + logging work.
        _EXPR_STRING_CACHE[cache_key] = None
        raise ValueError(f"no kmax compile information for '{obj_str}'")

    # Silence kmax informational prints identically to `/opt/venv/bin/kreader`.
    kmax_common.quiet = True
    lines: list[str] = []
    for unit in units:
        constraints = kmax_common.get_kmax_constraints(index.formulas, unit, view=False)
        constraint = z3.simplify(
            functools.reduce(lambda x, y: z3.And(x, y), constraints, z3.BoolVal(True))
        )
        lines.append(f"{unit} {constraint}")

    out = "\n".join(lines).strip()
    _EXPR_STRING_CACHE[cache_key] = out
    if not out:
        raise ValueError(f"no kmax compile information for '{obj_str}'")

    bool_expr, _ = BoolExpression.parse(" ".join(out.split(" ")[1:]))
    _LOGGER.debug("%s: %s", obj_str, bool_expr)
    return bool_expr


class IncludeGraphIndex:
    """Single-pass ``#include`` reverse dependency index over tracked ``.c``/``.h`` files.

    Replaces repeated per-header ``git grep`` subprocess calls with sorted tuples
    for ``<global>`` headers and ``"local"`` headers, allowing O(log N) prefix
    filtering per local header directory while preserving upstream DFS traversal
    and ``MAX_HEADER_SEARCH_DEPTH`` limits.
    """

    def __init__(
        self,
        repo_key: str,
        angle_map: dict[str, tuple[str, ...]],
        quote_map: dict[str, tuple[str, ...]],
    ) -> None:
        """Store sorted immutable angle-bracket and quoted-include lookup tables."""
        self.repo_key = repo_key
        # Frozen tuples make shared read-only state safe across CoW fork() workers.
        self.angle_map = angle_map
        self.quote_map = quote_map

    @classmethod
    def from_repo(cls, repo: str | pathlib.Path) -> IncludeGraphIndex:
        """Scan all ``^#include `` lines in ``*.c`` and ``*.h`` via one ``git grep``.

        Args:
            repo: Checked-out Linux kernel repository directory.

        Returns:
            Sorted, deduplicated ``IncludeGraphIndex`` for ``repo``.

        Raises:
            RuntimeError: If ``git grep`` fails with exit status ``> 1``.
        """
        repo_key = _normalize_repo_key(repo)
        cmd = ["git", "-C", repo_key, "grep", "-I", "-e", "^#include ", "--", "*.c", "*.h"]
        # Replace malformed UTF-8 bytes inside legacy comments instead of crashing.
        proc = subprocess.run(cmd, capture_output=True, text=True, errors="replace")
        # git grep returns exit code 1 when zero matches exist (e.g., tiny test repos).
        if proc.returncode > 1:
            raise RuntimeError(f"git grep returned with exit code {proc.returncode}: {proc.stderr}")

        angle_tmp: dict[str, set[str]] = defaultdict(set)
        quote_tmp: dict[str, set[str]] = defaultdict(set)

        for line in proc.stdout.splitlines():
            # Splitting on ":#include " stays unambiguous because lines match "^#include ".
            filepath, sep, rest = line.partition(":#include ")
            if not sep:
                continue
            if rest.startswith("<"):
                end = rest.find(">", 1)
                if end != -1:
                    angle_tmp[rest[1:end]].add(filepath)
            elif rest.startswith('"'):
                end = rest.find('"', 1)
                if end != -1:
                    quoted = rest[1:end]
                    quote_tmp[quoted.rsplit("/", 1)[-1]].add(filepath)

        # Freeze sorted tuples so DFS order matches lexicographical `git grep` output.
        return cls(
            repo_key=repo_key,
            angle_map={k: tuple(sorted(v)) for k, v in angle_tmp.items()},
            quote_map={k: tuple(sorted(v)) for k, v in quote_tmp.items()},
        )

    def _direct_includers(self, header: str) -> tuple[str, ...]:
        """Return sorted direct includer paths matching upstream global/local rules."""
        header_path = pathlib.Path(header)
        is_global = len(header_path.parents) >= 2 and str(header_path.parents[-2]) == "include"
        if is_global:
            include = "/".join(header_path.parts[1:])
            return self.angle_map.get(include, ())

        candidates = self.quote_map.get(header_path.name, ())
        parent_str = header_path.parent.as_posix()
        if parent_str in ("", "."):
            return candidates

        # Restrict sorted candidates to files located under header_path.parent via bisect.
        prefix = f"{parent_str.rstrip('/')}/"
        start = bisect.bisect_left(candidates, prefix)
        end = start
        while end < len(candidates) and candidates[end].startswith(prefix):
            end += 1
        return candidates[start:end]

    def query(
        self,
        header: str,
        checked_headers: list[str] | None,
        *,
        max_depth: int,
        depth_exc_cls: type[Exception],
    ) -> list[str]:
        """Recursively collect ``.c`` files impacted by ``header``.

        Preserves exact upstream ``checked_headers`` cycle tracking and raises
        ``depth_exc_cls`` once more than ``max_depth`` headers have been visited.
        """
        # Reproduce upstream `if not checked_headers` guard for fresh traversal calls.
        if not checked_headers:
            checked_headers = []

        files: list[str] = []
        for candidate in self._direct_includers(header):
            filepath = pathlib.Path(candidate)
            if filepath.suffix == ".c":
                files.append(candidate)
            elif filepath.suffix == ".h" and candidate not in checked_headers:
                checked_headers.append(candidate)
                if len(checked_headers) > max_depth:
                    raise depth_exc_cls("header search depth exceeded")
                files.extend(
                    self.query(
                        candidate,
                        checked_headers,
                        max_depth=max_depth,
                        depth_exc_cls=depth_exc_cls,
                    )
                )
        return list(set(files))


def get_or_build_include_index(repo: str | pathlib.Path) -> IncludeGraphIndex:
    """Return a cached ``IncludeGraphIndex`` or build it once from ``repo``."""
    key = _normalize_repo_key(repo)
    index = _INCLUDE_INDICES.get(key)
    if index is None:
        index = IncludeGraphIndex.from_repo(key)
        _INCLUDE_INDICES[key] = index
    return index


def accelerated_header_impacted_files(
    repo: str,
    header: str,
    checked_headers: list[str] | None = None,
) -> list[str]:
    """In-process replacement for ``cve_triage.triage.git.header_impacted_files``."""
    import cve_triage.triage.git as git_mod

    index = get_or_build_include_index(repo)
    return index.query(
        header,
        checked_headers,
        max_depth=git_mod.MAX_HEADER_SEARCH_DEPTH,
        depth_exc_cls=git_mod.HeaderSearchDepthException,
    )


def _cached_merge_base(repo: str, start_rev: str, target_rev: str) -> str:
    """Memoized per-worker wrapper around ``git merge-base <start> <target>``."""
    repo_key = _normalize_repo_key(repo)
    cache_key = (repo_key, start_rev, target_rev)
    cached = _MERGE_BASE_CACHE.get(cache_key)
    if cached is not None:
        ok, payload = cached
        if not ok:
            raise RuntimeError(payload)
        return payload

    cmd = ["git", "-C", repo, "merge-base", start_rev, target_rev]
    proc = subprocess.run(cmd, capture_output=True, text=True, errors="replace")
    if proc.returncode != 0:
        err_msg = f"git merge-base returned with exit code {proc.returncode}: {proc.stderr}"
        _MERGE_BASE_CACHE[cache_key] = (False, err_msg)
        raise RuntimeError(err_msg)

    merge_base = proc.stdout.strip()
    _MERGE_BASE_CACHE[cache_key] = (True, merge_base)
    return merge_base


def accelerated_track_file_at_revision(
    repo: str,
    start_rev: str,
    target_rev: str,
    filename: str,
) -> str | None:
    """Memoized replacement for ``cve_triage.triage.git.track_file_at_revision``.

    Caches both ``git merge-base`` and ``git log --follow`` results (including
    fail-closed ``RuntimeError`` cases such as missing promisor rename blobs).

    Args:
        repo: Kernel repository directory path.
        start_rev: Fixing commit SHA where ``filename`` appears.
        target_rev: Evaluated kernel revision tag or SHA.
        filename: Repository-relative path to track backwards in history.

    Returns:
        Historical path at ``target_rev``, or ``None`` if added/copied later.

    Raises:
        RuntimeError: Re-raises cached or live Git failures so partial clones stay fail-closed.
    """
    import cve_triage.triage.git as git_mod

    repo_key = _normalize_repo_key(repo)
    cache_key = (repo_key, start_rev, target_rev, filename)
    cached = _TRACK_FILE_CACHE.get(cache_key)
    if cached is not None:
        ok, payload = cached
        if not ok:
            # Propagate cached failure to preserve upstream under_investigation fallback.
            raise RuntimeError(str(payload))
        return payload

    merge_base = _cached_merge_base(repo, start_rev, target_rev)
    cmd = [
        "git",
        "-C",
        repo,
        "log",
        "--follow",
        "--oneline",
        "--name-status",
        f"{merge_base}..{start_rev}",
        "--",
        filename,
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True, errors="replace")
    if proc.returncode != 0:
        err_msg = f"git log returned with exit code {proc.returncode}: {proc.stderr}"
        # Cache failure per worker to avoid repeating blocked promisor object lookups.
        _TRACK_FILE_CACHE[cache_key] = (False, err_msg)
        raise RuntimeError(err_msg)

    lines = proc.stdout.splitlines()
    new_filename: str | None = filename
    # Pair commit summary line with its single --name-status line exactly as upstream does.
    for idx, first_line in enumerate(lines[::2]):
        name_status = git_mod.GitNameStatus.parse("\n".join([first_line, lines[2 * idx + 1]]))
        if name_status.added or name_status.copied:
            new_filename = None
            break
        if name_status.renamed:
            new_filename = name_status.renamed[0][0]

    _TRACK_FILE_CACHE[cache_key] = (True, new_filename)
    return new_filename


def accelerated_changed_files_at_revision(repo: str, rev: str) -> list[str]:
    """Memoized replacement for ``cve_triage.triage.git.changed_files_at_revision``."""
    repo_key = _normalize_repo_key(repo)
    cache_key = (repo_key, rev)
    cached = _CHANGED_FILES_CACHE.get(cache_key)
    if cached is not None:
        # Return a mutable list copy so caller mutations never alter cached tuples.
        return list(cached)

    cmd = ["git", "-C", repo, "show", "--oneline", "--name-only", rev, "--"]
    proc = subprocess.run(cmd, capture_output=True, text=True, errors="replace")
    if proc.returncode != 0:
        raise RuntimeError(f"git show returned with exit code {proc.returncode}: {proc.stderr}")

    files = tuple(proc.stdout.splitlines()[1:])
    _CHANGED_FILES_CACHE[cache_key] = files
    return list(files)


def _patch_pre_fork_setup(ks_mod: Any, cache_mod: Any) -> None:
    """Wrap ``KernelSource.setup_repo`` and ``CacheManager`` to preload before ``fork()``."""
    orig_setup_repo = ks_mod.KernelSource.setup_repo
    if not getattr(orig_setup_repo, "_kernelvex_accel_patched", False):

        def _wrapped_setup_repo(self: Any, no_clone: bool, tempdir: Any) -> pathlib.Path:
            repo_path = orig_setup_repo(self, no_clone, tempdir)
            # Build header reverse index once in parent after target rev checkout.
            get_or_build_include_index(repo_path)
            return repo_path

        _wrapped_setup_repo._kernelvex_accel_patched = True  # type: ignore[attr-defined]
        ks_mod.KernelSource.setup_repo = _wrapped_setup_repo

    orig_create_kmax = cache_mod.CacheManager.create_kmax_cache
    if not getattr(orig_create_kmax, "_kernelvex_accel_patched", False):

        def _wrapped_create_kmax(
            self: Any, version: Any, kmax_formulas: str | None, root: str = ".cache"
        ) -> Any:
            cache_obj = orig_create_kmax(self, version, kmax_formulas, root)
            if cache_obj.exists():
                # Unpickle SMT2 formulas into parent CoW memory before Pool forks.
                get_or_load_kmax_index(cache_obj.path)
            return cache_obj

        _wrapped_create_kmax._kernelvex_accel_patched = True  # type: ignore[attr-defined]
        cache_mod.CacheManager.create_kmax_cache = _wrapped_create_kmax

    orig_copy_cache = cache_mod.CacheManager.copy_cache
    if not getattr(orig_copy_cache, "_kernelvex_accel_patched", False):

        def _wrapped_copy_cache(self: Any, src: pathlib.Path, dst: pathlib.Path | None) -> None:
            orig_copy_cache(self, src, dst)
            if dst and pathlib.Path(dst).is_file():
                # Preload freshly generated kmax formulas and alias the temp src path
                # passed into Pool workers when cache was cold.
                idx = get_or_load_kmax_index(dst)
                _KMAX_INDICES[str(pathlib.Path(src).resolve())] = idx

        _wrapped_copy_cache._kernelvex_accel_patched = True  # type: ignore[attr-defined]
        cache_mod.CacheManager.copy_cache = _wrapped_copy_cache


def install_accelerators() -> None:
    """Install all in-process ``cve_triage`` accelerator patches idempotently.

    Updates both defining modules (``kmax``, ``git``) and ``from ... import``
    bindings already imported into ``checks.introduced_by`` and ``checks.fixed_by``.
    """
    import cve_triage.triage.cache_manager as cache_mod
    import cve_triage.triage.checks.fixed_by as fixed_by_mod
    import cve_triage.triage.checks.introduced_by as introduced_by_mod
    import cve_triage.triage.git as git_mod
    import cve_triage.triage.kernel_source as ks_mod
    import cve_triage.triage.kmax as kmax_mod

    # Patch Kmax lookup both at its definition and every check module binding.
    for mod in (kmax_mod, introduced_by_mod, fixed_by_mod):
        mod.config_for_file = accelerated_config_for_file

    # Patch header graph lookup, file tracking, and commit file listing across callers.
    for mod in (git_mod, introduced_by_mod, fixed_by_mod):
        mod.header_impacted_files = accelerated_header_impacted_files
        mod.changed_files_at_revision = accelerated_changed_files_at_revision

    for mod in (git_mod, fixed_by_mod):
        mod.track_file_at_revision = accelerated_track_file_at_revision

    _patch_pre_fork_setup(ks_mod, cache_mod)


def main() -> None:
    """Entrypoint executed via ``python -m kernelvex.accel triage ...``."""
    from cve_triage.cli.entry import main as upstream_main

    # Install hooks before argparse/command execution so TriageRunner sees them.
    install_accelerators()
    upstream_main()


if __name__ == "__main__":
    main()
