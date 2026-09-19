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
import threading
import time
from collections.abc import Callable, Iterator
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from filecleaner import config as config_mod
from filecleaner import native_walk, safety
from filecleaner import rules as rules_mod
from filecleaner.models import Candidate, Rule, ScanResult
from filecleaner.volumes import default_scan_roots

ProgressCallback = Callable[[str, float | None], None]

_MAX_ERRORS = 200
_LISTING_RETRIES = 8
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
            entries = _list_dir(current)
        except OSError:
            continue
        for entry in entries:
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
    return total, newest


@dataclass
class _ScanCounter:
    """Directories walked so far across the *entire* scan (every rule, every
    root) plus the total predicted by a prior counting pass, if any.

    Shared by reference across every ``_WalkContext`` created during one
    ``run_scan`` call, so percent-complete reflects overall progress rather
    than resetting at each rule or root. Rule/root walks now run concurrently
    (see ``_run_targets``), so ``done`` is incremented from multiple threads —
    the lock makes that read-modify-write safe.
    """

    done: int = 0
    total: int | None = None
    _lock: threading.Lock = field(default_factory=threading.Lock)

    def increment(self) -> None:
        with self._lock:
            self.done += 1

    def advance_to(self, done: int) -> None:
        """For a walker that counts for itself and reports a running total."""
        with self._lock:
            self.done = max(self.done, done)

    def percent(self) -> float | None:
        if not self.total:
            return None
        # Directories can appear or disappear between the counting pass and
        # the real scan (e.g. a browser writes new cache subfolders), so the
        # live count can creep past the earlier estimate — clamp rather than
        # show a nonsensical >100%.
        return min(100.0, 100.0 * self.done / self.total)


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
    counter: _ScanCounter
    count_only: bool = False
    dirs_seen: int = 0

    def is_excluded(self, rel: str) -> bool:
        return any(m.matches(rel) for m in self.excludes)

    def record_error(self, message: str) -> None:
        if len(self.result.errors) < _MAX_ERRORS:
            self.result.errors.append(message)

    def tick(self, rel: str) -> None:
        self.dirs_seen += 1
        self.counter.increment()
        if self.progress is not None and self.dirs_seen % _PROGRESS_EVERY_DIRS == 0:
            _report_walking(self.progress, self.rule, rel, self.counter)


def _report_walking(progress: ProgressCallback, rule: Rule, rel: str, counter: _ScanCounter) -> None:
    message = f"{rule.label}: scanning {rel or '.'}"
    percent = counter.percent()
    if percent is None:
        # No counting pre-pass to measure against: say how far the walk has
        # got instead, so progress is still visibly live.
        message = f"{counter.done:,} folders · {message}"
    progress(message, percent)


def _list_dir(path: str) -> list[os.DirEntry[str]]:
    """Every entry of ``path``. Inside another app's sandbox
    (``~/Library/Containers``) macOS now and then hangs the opening of a
    directory for several seconds and then fails it with EINTR; asked again
    it answers at once. So an interrupted listing is retried — reporting it
    would call a readable directory unreadable and leave it unscanned."""
    for _ in range(_LISTING_RETRIES):
        try:
            with os.scandir(path) as it:
                return list(it)
        except InterruptedError:
            continue
    with os.scandir(path) as it:
        return list(it)


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
    # Symlinks are resolved once, here, rather than once per entry. Every
    # entry below is reached through non-symlink names only (symlinked
    # entries are skipped), so ``resolved_dir + "/" + name`` is fully
    # resolved by construction and the deny-list can be checked against it
    # with no filesystem access. ``dir_path`` stays as the user spelled it:
    # that is what gets reported. Quarantine re-resolves and re-checks every
    # candidate before it moves anything.
    try:
        resolved_start = str(start.resolve(strict=False)).rstrip("/")  # "" for the root directory
    except (OSError, RuntimeError):
        return

    start_depth = len(start_rel.split("/")) if start_rel else 0
    stack: list[tuple[str, str, str, int]] = [(str(start), resolved_start, start_rel, start_depth)]
    while stack:
        dir_path, resolved_dir, dir_rel, depth = stack.pop()
        ctx.tick(dir_rel)
        try:
            entries = _list_dir(dir_path)
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
            resolved = f"{resolved_dir}/{entry.name}"
            if safety.is_protected_resolved(resolved, extra_protected=ctx.extra_protected):
                continue

            matched = ctx.matcher.matches(rel)
            if is_dir:
                if matched and ctx.rule.kind == "dir":
                    if not ctx.count_only:
                        _emit(ctx, Path(entry.path), is_dir=True)
                    continue  # never descend into something we already report as a whole
                if entry.name in _NEVER_DESCEND:
                    continue
                if ctx.matcher.max_depth is None or depth + 1 < ctx.matcher.max_depth:
                    stack.append((entry.path, resolved, rel, depth + 1))
                continue
            if matched and ctx.rule.kind == "file" and not ctx.count_only:
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
    candidate = _candidate(ctx.rule, path, is_dir=is_dir, size=size, mtime=mtime, now=ctx.now)
    if candidate is not None:
        ctx.result.candidates.append(candidate)


def _candidate(rule: Rule, path: Path, *, is_dir: bool, size: int, mtime: float, now: float) -> Candidate | None:
    """A match becomes a candidate only if it clears the rule's thresholds."""
    age_days = (now - mtime) / 86400
    if age_days < rule.min_age_days or size < rule.min_size_bytes:
        return None
    return Candidate(
        path=path,
        size_bytes=size,
        is_dir=is_dir,
        mtime=mtime,
        rule_id=rule.id,
        category=rule.category,
        risk=rule.risk,
    )


def scan_rule(
    base: Path,
    rule: Rule,
    result: ScanResult,
    extra_protected: tuple[Path, ...],
    *,
    progress: ProgressCallback | None = None,
    now: float | None = None,
    counter: _ScanCounter | None = None,
    count_only: bool = False,
) -> None:
    """Evaluate one rule against one root, appending matches to ``result``.

    ``count_only`` skips the (comparatively expensive) stat/emit step and
    just walks directories, for ``count_total_dirs``'s pre-pass.
    """
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
            counter=counter if counter is not None else _ScanCounter(),
            count_only=count_only,
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
        return rules_mod.apply_param_overrides([r for r in available if r.id in only_rules], config)
    selected: list[Rule] = []
    for rule in available:
        enabled = config_mod.is_rule_enabled(config, rule.id, rule.enabled_by_default)
        if enabled or include_disabled:
            selected.append(rule)
    return rules_mod.apply_param_overrides(selected, config)


def _scan_setup(
    config: dict[str, Any], extra_excludes: tuple[Path, ...] = (), *, root: Path | None = None
) -> tuple[Path, list[Path], bool, list[Path], tuple[Path, ...]]:
    """Resolve the effective root for "home"-scoped rules and, when that root
    really is the home directory, every external volume for "each_volume"
    rules too.

    ``root`` defaults to the current working directory — not the home
    directory — so a scan run from inside some folder is scoped to that
    folder by default. Passing the actual home directory (``root=Path.home()``,
    which is what a bare ``fclean scan`` run *from* the home directory
    produces) restores the traditional whole-machine scan across every
    detected volume; any other root only ever scans that one directory tree,
    since "each_volume" rules (external drive trash, etc.) don't make sense
    scoped to an arbitrary folder.
    """
    home = Path.home()
    effective_root = (root if root is not None else Path.cwd()).expanduser().resolve()
    extra_protected = (
        config_mod.extra_protected_paths(config) + config_mod.data_paths_to_protect(config) + tuple(extra_excludes)
    )
    if _same_path(effective_root, home):
        roots = default_scan_roots(config.get("scan_roots") or [])
        root_in_roots = any(_same_path(r, effective_root) for r in roots)
        volume_roots = [r for r in roots if not _same_path(r, effective_root)]
        return effective_root, roots, root_in_roots, volume_roots, extra_protected
    return effective_root, [effective_root], True, [], extra_protected


def _iter_targets(
    selected: list[Rule], root: Path, root_in_roots: bool, volume_roots: list[Path]
) -> Iterator[tuple[Rule, Path]]:
    """Every (rule, root) pair a scan will walk, in the order it will walk them."""
    for rule in selected:
        if rule.scope == "home":
            if root_in_roots:
                yield rule, root
        elif rule.scope == "each_volume":
            for vol_root in volume_roots:
                yield rule, vol_root


def _locked_progress(progress: ProgressCallback) -> ProgressCallback:
    """Serialize calls to a progress callback that will now be invoked from
    multiple worker threads at once — callers (a Rich ``\\r`` printer, a
    Textual ``call_from_thread``) were written assuming one caller at a time."""
    lock = threading.Lock()

    def wrapped(message: str, percent: float | None) -> None:
        with lock:
            progress(message, percent)

    return wrapped


def _run_targets_native(
    targets: list[tuple[Rule, Path]],
    extra_protected: tuple[Path, ...],
    *,
    progress: ProgressCallback | None,
    counter: _ScanCounter,
) -> tuple[list[Candidate], list[str]] | None:
    """The same walks as the Python path below, run by the native helper
    (see ``native_walk``). None when there is no helper or it failed, in
    which case the caller walks in Python.

    The helper is an accelerator, not an authority: the deny index it is
    given only lets it prune, and every path it reports is checked here —
    inside the walk's own root, and against the authoritative, resolving
    ``safety.is_protected`` — before it can become a candidate."""
    walks: list[native_walk.Walk] = []
    owners: list[Rule] = []
    for rule, base in targets:
        for pattern in rule.include_globs:
            walks.append(native_walk.Walk(str(base), pattern, rule.kind, tuple(rule.exclude_globs)))
            owners.append(rule)

    def on_progress(done: int, walk: int, rel: str) -> None:
        counter.advance_to(done)
        if progress is not None and 0 <= walk < len(owners):
            _report_walking(progress, owners[walk], rel, counter)

    deny_home, deny_prefixes = safety.deny_index_keys(extra_protected)
    outcome = native_walk.scan(
        walks,
        deny_home=deny_home,
        deny_prefixes=deny_prefixes,
        never_descend=sorted(_NEVER_DESCEND),
        on_progress=on_progress,
    )
    if outcome is None:
        return None
    counter.advance_to(outcome.dirs)

    now = time.time()
    candidates: list[Candidate] = []
    for match in sorted(outcome.matches, key=lambda m: (m.walk, m.path)):
        walk_root = walks[match.walk].base.rstrip("/")
        if not match.path.startswith(walk_root + "/"):
            continue
        path = Path(match.path)
        if safety.is_protected(path, extra_protected=extra_protected):
            continue
        candidate = _candidate(
            owners[match.walk], path, is_dir=match.is_dir, size=match.size, mtime=match.mtime, now=now
        )
        if candidate is not None:
            candidates.append(candidate)
    errors = [
        f"{owners[e.walk].id}: cannot read {e.path}: {os.strerror(e.errno) if e.errno else 'unknown error'}"
        for e in sorted(outcome.errors, key=lambda e: (e.walk, e.path))
    ]
    return candidates, errors[:_MAX_ERRORS]


def _run_targets(
    targets: list[tuple[Rule, Path]],
    extra_protected: tuple[Path, ...],
    *,
    progress: ProgressCallback | None,
    counter: _ScanCounter,
    count_only: bool,
    max_workers: int,
) -> tuple[list[Candidate], list[str]]:
    """Run every ``(rule, root)`` walk concurrently — this is I/O-bound work
    (``os.scandir``/``stat`` syscalls), and CPython releases the GIL for
    those, so a thread pool gives real wall-clock parallelism without the
    complexity of multiprocessing. Each task gets its own ``ScanResult`` (no
    lock needed on the hot per-directory/per-file path); results are merged
    afterwards in submission order, so output stays identical to a
    sequential run — only faster."""
    if not targets:
        return [], []
    locked_progress = _locked_progress(progress) if progress is not None else None
    if not count_only:
        native = _run_targets_native(targets, extra_protected, progress=locked_progress, counter=counter)
        if native is not None:
            return native

    def _run_one(rule: Rule, root: Path) -> ScanResult:
        if locked_progress is not None:
            locked_progress(f"{rule.label}…", counter.percent())
        partial = ScanResult(scan_roots=[])
        scan_rule(root, rule, partial, extra_protected, progress=locked_progress, counter=counter, count_only=count_only)
        return partial

    candidates: list[Candidate] = []
    errors: list[str] = []
    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = [pool.submit(_run_one, rule, root) for rule, root in targets]
        for future in futures:
            partial = future.result()
            candidates.extend(partial.candidates)
            errors.extend(partial.errors)
    return candidates, errors


def count_total_dirs(
    config: dict[str, Any],
    *,
    only_rules: set[str] | None = None,
    include_disabled: bool = False,
    extra_excludes: tuple[Path, ...] = (),
    rules: tuple[Rule, ...] | None = None,
    root: Path | None = None,
) -> int:
    """Pre-pass: walk every directory a real scan would visit, without
    stat-ing matches, so ``run_scan`` can report true percent-complete.

    This is meaningfully cheaper than a real scan (no per-file ``stat``
    calls, no recursive size totals for matched directories) but it is not
    free — it still touches every directory a scan would. Nothing in File
    Cleaner calls it by default any more: without it, ``run_scan`` reports
    a running folder count instead. Call it only where a true percentage
    is worth walking the tree twice.
    """
    selected = select_rules(config, only_rules=only_rules, include_disabled=include_disabled, rules=rules)
    effective_root, _roots, root_in_roots, volume_roots, extra_protected = _scan_setup(
        config, extra_excludes, root=root
    )
    targets = list(_iter_targets(selected, effective_root, root_in_roots, volume_roots))
    counter = _ScanCounter()
    max_workers = config.get("scan_concurrency", 4)
    _run_targets(targets, extra_protected, progress=None, counter=counter, count_only=True, max_workers=max_workers)
    return counter.done


def run_scan(
    config: dict[str, Any],
    *,
    only_rules: set[str] | None = None,
    include_disabled: bool = False,
    extra_excludes: tuple[Path, ...] = (),
    progress: ProgressCallback | None = None,
    rules: tuple[Rule, ...] | None = None,
    total_dirs: int | None = None,
    root: Path | None = None,
) -> ScanResult:
    """Run every selected rule over the configured roots and return the
    coalesced, safety-filtered candidates. ``(rule, root)`` walks run
    concurrently, bounded by the ``scan_concurrency`` config key.

    ``root`` defaults to the current working directory (see ``_scan_setup``);
    pass the home directory to get the traditional whole-machine scan.

    ``total_dirs`` — typically from a prior ``count_total_dirs`` call — lets
    ``progress`` report a real percent-complete instead of just a message;
    omit it (the default) to get messages with no percentage, as before.
    """
    started = time.monotonic()
    selected = select_rules(config, only_rules=only_rules, include_disabled=include_disabled, rules=rules)
    effective_root, roots, root_in_roots, volume_roots, extra_protected = _scan_setup(
        config, extra_excludes, root=root
    )
    targets = list(_iter_targets(selected, effective_root, root_in_roots, volume_roots))

    result = ScanResult(scan_roots=list(roots))
    counter = _ScanCounter(total=total_dirs)
    max_workers = config.get("scan_concurrency", 4)

    result.candidates, result.errors = _run_targets(
        targets, extra_protected, progress=progress, counter=counter, count_only=False, max_workers=max_workers
    )
    result.errors = result.errors[:_MAX_ERRORS]

    result.candidates, result.overlaps_dropped = coalesce(result.candidates)
    result.duration_seconds = time.monotonic() - started
    if progress is not None:
        progress(f"Done: {len(result.candidates)} candidates", 100.0 if total_dirs else None)
    return result


def _same_path(a: Path, b: Path) -> bool:
    try:
        return a.resolve(strict=False) == b.resolve(strict=False)
    except OSError:
        return a == b
