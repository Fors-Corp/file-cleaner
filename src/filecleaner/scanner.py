"""The scan engine: walks scan roots and turns rule matches into sized
``Candidate`` objects.

Only path metadata (name, size, mtime) is ever read here — file contents
are never opened. Every match is checked against the hardcoded safety
deny-list before it's even reported as a candidate, not just before a
destructive action.

Design notes
------------
* One walk per (root, rule, include glob), implemented with ``os.scandir``
  and *pruning*: excluded and protected directories are never entered, and
  a directory that matched a ``kind="dir"`` rule is reported once and not
  descended into. This is what makes ``**/...`` patterns affordable on a
  large home directory.
* A rule's ``kind`` is honoured strictly: file rules only ever report files,
  dir rules only directories.
* After all rules ran, overlapping candidates are *coalesced*: an item that
  sits inside another candidate (or was matched by two rules) is dropped, so
  sizes are never double counted and nothing is moved twice.
* Directory age is the newest modification time anywhere inside the tree,
  not the directory's own mtime — an actively used cache with fresh files
  deep inside is never treated as stale.
"""

from __future__ import annotations

import contextlib
import os
import re
import time
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from filecleaner import config as config_mod
from filecleaner import rules as rules_mod
from filecleaner import safety
from filecleaner.models import Candidate, Rule, ScanResult
from filecleaner.volumes import default_scan_roots

ProgressCallback = Callable[[str], None]

_MAX_ERRORS = 200
_PROGRESS_EVERY_DIRS = 250
_NEVER_DESCEND = frozenset({".git"})
_WILDCARDS = ("*", "?", "[")


class UnknownRuleError(ValueError):
    """A rule id passed on the command line does not exist."""


# --------------------------------------------------------------------------
# Glob matching
# --------------------------------------------------------------------------


def _segment_to_regex(segment: str) -> str:
    out: list[str] = []
    i = 0
    while i < len(segment):
        ch = segment[i]
        if ch == "*":
            out.append("[^/]*")
        elif ch == "?":
            out.append("[^/]")
        elif ch == "[":
            end = segment.find("]", i + 1)
            if end == -1:
                out.append(re.escape(ch))
            else:
                body = segment[i + 1 : end]
                if body.startswith("!"):
                    body = "^" + body[1:]
                out.append("[" + body.replace("\\", "\\\\") + "]")
                i = end
        else:
            out.append(re.escape(ch))
        i += 1
    return "".join(out)


def glob_to_regex(pattern: str) -> str:
    """Translate a rule glob (relative, ``/``-separated) into a regex over
    relative POSIX paths.

    * ``*`` and ``?`` never cross a ``/``.
    * ``**`` as a whole segment matches zero or more directories.
    * A trailing ``/**`` also matches the directory itself, so exclusion
      patterns like ``Library/**`` prune the whole subtree.
    """
    pattern = pattern.strip("/")
    if pattern in ("", "**"):
        return r"^.*$"
    parts = pattern.split("/")
    regex = ""
    for index, segment in enumerate(parts):
        last = index == len(parts) - 1
        if segment == "**":
            if last:
                regex = regex.rstrip("/") + "(?:/.*)?"
            else:
                regex += "(?:[^/]+/)*"
            continue
        regex += _segment_to_regex(segment)
        if not last:
            regex += "/"
    return "^" + regex + "$"


@dataclass(frozen=True)
class GlobMatcher:
    pattern: str
    regex: re.Pattern[str]
    static_prefix: str  # leading wildcard-free segments (the walk start dir)
    max_depth: int | None  # None for recursive (``**``) patterns

    @classmethod
    def compile(cls, pattern: str) -> GlobMatcher:
        parts = pattern.strip("/").split("/")
        prefix_parts: list[str] = []
        for segment in parts:
            if segment == "**" or any(w in segment for w in _WILDCARDS):
                break
            prefix_parts.append(segment)
        recursive = "**" in parts
        return cls(
            pattern=pattern,
            regex=re.compile(glob_to_regex(pattern)),
            static_prefix="/".join(prefix_parts),
            max_depth=None if recursive else len(parts),
        )

    def matches(self, rel_posix: str) -> bool:
        return self.regex.match(rel_posix) is not None


# --------------------------------------------------------------------------
# Filesystem helpers
# --------------------------------------------------------------------------


def dir_stats(path: Path) -> tuple[int, float]:
    """Total apparent size and newest mtime of every regular file below
    ``path`` (symlinks are never followed). Public: also used by
    ``plan.revalidate`` to re-check a directory candidate's contents
    between a saved plan and ``apply``."""
    total = 0
    newest = 0.0
    with contextlib.suppress(OSError):
        newest = os.lstat(path).st_mtime
    stack = [str(path)]
    while stack:
        current = stack.pop()
        try:
            with os.scandir(current) as it:
                for entry in it:
                    try:
                        if entry.is_symlink():
                            continue
                        if entry.is_dir(follow_symlinks=False):
                            stack.append(entry.path)
                            continue
                        st = entry.stat(follow_symlinks=False)
                    except OSError:
                        continue
                    total += st.st_size
                    if st.st_mtime > newest:
                        newest = st.st_mtime
        except OSError:
            continue
    return total, newest


@dataclass
class _WalkContext:
    rule: Rule
    base: Path
    matcher: GlobMatcher
    excludes: tuple[GlobMatcher, ...]
    extra_protected: tuple[Path, ...]
    result: ScanResult
    progress: ProgressCallback | None
    now: float
    dirs_seen: int = 0

    def is_excluded(self, rel: str) -> bool:
        return any(m.matches(rel) for m in self.excludes)

    def record_error(self, message: str) -> None:
        if len(self.result.errors) < _MAX_ERRORS:
            self.result.errors.append(message)

    def tick(self, rel: str) -> None:
        self.dirs_seen += 1
        if self.progress is not None and self.dirs_seen % _PROGRESS_EVERY_DIRS == 0:
            self.progress(f"{self.rule.label}: scanning {rel or '.'}")


def _iter_dir(path: str) -> Iterator[os.DirEntry[str]]:
    with os.scandir(path) as it:
        yield from it


def _walk_rule_pattern(ctx: _WalkContext) -> None:
    """Depth-first walk from the pattern's static prefix, emitting candidates."""
    start_rel = ctx.matcher.static_prefix
    start = ctx.base / start_rel if start_rel else ctx.base
    try:
        if not start.is_dir() or start.is_symlink():
            return
    except OSError:
        return
    if start_rel and (ctx.is_excluded(start_rel) or safety.is_protected(start, extra_protected=ctx.extra_protected)):
        return

    start_depth = len(start_rel.split("/")) if start_rel else 0
    stack: list[tuple[str, str, int]] = [(str(start), start_rel, start_depth)]
    while stack:
        dir_path, dir_rel, depth = stack.pop()
        ctx.tick(dir_rel)
        try:
            entries = list(_iter_dir(dir_path))
        except OSError as exc:
            ctx.record_error(f"{ctx.rule.id}: cannot read {dir_path}: {exc.strerror or exc}")
            continue
        for entry in entries:
            rel = f"{dir_rel}/{entry.name}" if dir_rel else entry.name
            try:
                if entry.is_symlink():
                    continue
                is_dir = entry.is_dir(follow_symlinks=False)
            except OSError:
                continue
            if ctx.is_excluded(rel):
                continue
            if safety.is_protected(Path(entry.path), extra_protected=ctx.extra_protected):
                continue

            matched = ctx.matcher.matches(rel)
            if is_dir:
                if matched and ctx.rule.kind == "dir":
                    _emit(ctx, Path(entry.path), is_dir=True)
                    continue  # never descend into something we already report as a whole
                if entry.name in _NEVER_DESCEND:
                    continue
                if ctx.matcher.max_depth is None or depth + 1 < ctx.matcher.max_depth:
                    stack.append((entry.path, rel, depth + 1))
                continue
            if matched and ctx.rule.kind == "file":
                _emit(ctx, Path(entry.path), is_dir=False)


def _emit(ctx: _WalkContext, path: Path, *, is_dir: bool) -> None:
    try:
        st = os.lstat(path)
    except OSError:
        return
    if is_dir:
        size, newest_mtime = dir_stats(path)
        mtime = max(st.st_mtime, newest_mtime)
    else:
        size, mtime = st.st_size, st.st_mtime

    age_days = (ctx.now - mtime) / 86400
    if age_days < ctx.rule.min_age_days:
        return
    if size < ctx.rule.min_size_bytes:
        return
    ctx.result.candidates.append(
        Candidate(
            path=path,
            size_bytes=size,
            is_dir=is_dir,
            mtime=mtime,
            rule_id=ctx.rule.id,
            category=ctx.rule.category,
            risk=ctx.rule.risk,
        )
    )


def scan_rule(
    base: Path,
    rule: Rule,
    result: ScanResult,
    extra_protected: tuple[Path, ...],
    *,
    progress: ProgressCallback | None = None,
    now: float | None = None,
) -> None:
    """Evaluate one rule against one root, appending matches to ``result``."""
    try:
        if not base.is_dir():
            return
    except OSError:
        return
    excludes = tuple(GlobMatcher.compile(p) for p in rule.exclude_globs)
    for pattern in rule.include_globs:
        ctx = _WalkContext(
            rule=rule,
            base=base,
            matcher=GlobMatcher.compile(pattern),
            excludes=excludes,
            extra_protected=extra_protected,
            result=result,
            progress=progress,
            now=time.time() if now is None else now,
        )
        _walk_rule_pattern(ctx)


# --------------------------------------------------------------------------
# Coalescing
# --------------------------------------------------------------------------


def coalesce(candidates: list[Candidate]) -> tuple[list[Candidate], int]:
    """Drop candidates nested inside another candidate, and exact duplicates.

    Shallower paths win; among equal depth the earlier match (= the more
    specific rule, given rule ordering) wins. Returns (kept, dropped_count).
    """
    ordered = sorted(enumerate(candidates), key=lambda ic: (len(ic[1].path.parts), ic[0]))
    kept: dict[Path, Candidate] = {}
    dropped = 0
    for _index, cand in ordered:
        if cand.path in kept or any(parent in kept for parent in cand.path.parents):
            dropped += 1
            continue
        kept[cand.path] = cand
    return list(kept.values()), dropped


# --------------------------------------------------------------------------
# Entry point
# --------------------------------------------------------------------------


def select_rules(
    config: dict[str, Any],
    *,
    only_rules: set[str] | None = None,
    include_disabled: bool = False,
    rules: tuple[Rule, ...] | None = None,
) -> list[Rule]:
    """Which rules a scan should run, honouring overrides and explicit filters."""
    available = rules if rules is not None else rules_mod.all_rules(config)
    if only_rules is not None:
        known = {r.id for r in available}
        unknown = sorted(only_rules - known)
        if unknown:
            raise UnknownRuleError(f"unknown rule id(s): {', '.join(unknown)}")
        return [r for r in available if r.id in only_rules]
    selected: list[Rule] = []
    for rule in available:
        enabled = config_mod.is_rule_enabled(config, rule.id, rule.enabled_by_default)
        if enabled or include_disabled:
            selected.append(rule)
    return selected


def run_scan(
    config: dict[str, Any],
    *,
    only_rules: set[str] | None = None,
    include_disabled: bool = False,
    extra_excludes: tuple[Path, ...] = (),
    progress: ProgressCallback | None = None,
    rules: tuple[Rule, ...] | None = None,
) -> ScanResult:
    """Run every selected rule over the configured roots and return the
    coalesced, safety-filtered candidates."""
    started = time.monotonic()
    selected = select_rules(config, only_rules=only_rules, include_disabled=include_disabled, rules=rules)

    home = Path.home()
    roots = default_scan_roots(config.get("scan_roots") or [])
    home_in_roots = any(_same_path(r, home) for r in roots)
    volume_roots = [r for r in roots if not _same_path(r, home)]

    result = ScanResult(scan_roots=list(roots))
    extra_protected = (
        config_mod.extra_protected_paths(config) + config_mod.data_paths_to_protect(config) + tuple(extra_excludes)
    )

    for rule in selected:
        if progress is not None:
            progress(f"{rule.label}…")
        if rule.scope == "home":
            if home_in_roots:
                scan_rule(home, rule, result, extra_protected, progress=progress)
        elif rule.scope == "each_volume":
            for vol_root in volume_roots:
                scan_rule(vol_root, rule, result, extra_protected, progress=progress)

    result.candidates, result.overlaps_dropped = coalesce(result.candidates)
    result.duration_seconds = time.monotonic() - started
    if progress is not None:
        progress(f"Done: {len(result.candidates)} candidates")
    return result


def _same_path(a: Path, b: Path) -> bool:
    try:
        return a.resolve(strict=False) == b.resolve(strict=False)
    except OSError:
        return a == b
