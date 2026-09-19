"""Hash-based duplicate file finder.

Read-only: never moves or modifies anything. Files are only ever hashed
(never printed or logged with their contents) — hashing is a three-stage
funnel (size -> partial hash -> full hash) so most non-duplicate files are
ruled out without ever being fully read.
"""

from __future__ import annotations

import hashlib
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

from filecleaner import config as config_mod
from filecleaner import filewalk, safety
from filecleaner.models import DuplicateGroup, Skipped

ProgressCallback = Callable[[str], None]
_PARTIAL_HASH_BYTES = 65536
_FULL_HASH_CHUNK = 1024 * 1024
_PROGRESS_EVERY_FILES = 500


def _partial_hash(path: Path) -> str | None:
    try:
        with path.open("rb") as f:
            return hashlib.sha256(f.read(_PARTIAL_HASH_BYTES)).hexdigest()
    except OSError:
        return None


def _full_hash(path: Path) -> str | None:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as f:
            while chunk := f.read(_FULL_HASH_CHUNK):
                digest.update(chunk)
    except OSError:
        return None
    return digest.hexdigest()


def find_duplicates(
    roots: list[Path],
    config: dict[str, Any],
    *,
    min_size_bytes: int = 4096,
    max_groups: int | None = None,
    progress: ProgressCallback | None = None,
) -> list[DuplicateGroup]:
    """Group files whose contents are identical.

    A duplicate is a DIFFERENT physical file with the same bytes. Each
    physical file is considered once, however many paths lead to it (see
    ``filewalk``) — so two hard links to one inode are one file, not
    duplicates: removing one name would free no space.
    """
    extra_protected = config_mod.extra_protected_paths(config) + config_mod.data_paths_to_protect(config)
    max_hash_bytes = config.get("hash_duplicates_max_bytes", 2_000_000_000)

    size_buckets: dict[int, list[Path]] = {}
    files_seen = 0
    for file_path, st in filewalk.walk_unique_files(
        roots, extra_protected=extra_protected, min_size=min_size_bytes
    ):
        files_seen += 1
        if progress is not None and files_seen % _PROGRESS_EVERY_FILES == 0:
            progress(f"scanned {files_seen} files, comparing sizes…")
        if st.st_size < min_size_bytes:
            continue
        if safety.is_protected(file_path, extra_protected=extra_protected):
            continue
        size_buckets.setdefault(st.st_size, []).append(file_path)

    max_workers = config.get("scan_concurrency", 4)

    # Same-size candidates only — hashing is CPU/IO work per file, and
    # hashlib's OpenSSL backend releases the GIL for it, so a thread pool
    # gives real parallelism here instead of hashing one file at a time.
    partial_candidates = [(size, path) for size, paths in size_buckets.items() if len(paths) >= 2 for path in paths]
    partial_buckets: dict[tuple[int, str], list[Path]] = {}
    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        partial_hashes = pool.map(_partial_hash, (path for _size, path in partial_candidates))
        for (size, path), partial in zip(partial_candidates, partial_hashes, strict=True):
            if partial is None:
                continue
            partial_buckets.setdefault((size, partial), []).append(path)

    if progress is not None:
        progress("comparing full contents of same-size candidates…")

    full_candidates = [
        (size, path)
        for (size, _partial), paths in partial_buckets.items()
        if len(paths) >= 2 and size <= max_hash_bytes
        for path in paths
    ]
    full_hashes_by_size: dict[int, dict[str, list[Path]]] = {}
    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        full_hashes = pool.map(_full_hash, (path for _size, path in full_candidates))
        for (size, path), full in zip(full_candidates, full_hashes, strict=True):
            if full is None:
                continue
            full_hashes_by_size.setdefault(size, {}).setdefault(full, []).append(path)

    groups: list[DuplicateGroup] = []
    for size, full_buckets in full_hashes_by_size.items():
        for full_hash, group_paths in full_buckets.items():
            distinct = _distinct_files(group_paths)
            if len(distinct) > 1:
                groups.append(DuplicateGroup(sha256=full_hash, size_bytes=size, paths=distinct))

    groups.sort(key=lambda g: (g.wasted_bytes, g.sha256), reverse=True)
    if max_groups:
        groups = groups[:max_groups]
    return groups


KEEP_STRATEGIES = ("oldest", "newest", "shortest-path")


def _distinct_files(paths: list[Path]) -> list[Path]:
    """``paths`` sorted, keeping one path per physical file.

    ``filewalk`` already visits each file once, so this normally removes
    nothing. It is here because "these are two different files" is the
    claim a permanent delete rests on, and it should not rest on the walk
    alone — least of all when the walk was done by the native helper, whose
    word is not taken for anything that matters. It costs one ``stat`` per
    member of a finished group, which is next to nothing."""
    distinct: list[Path] = []
    seen: set[filewalk.FileIdentity] = set()
    for path in sorted(paths):
        file_id = _identity_of(path)
        if file_id is None or file_id in seen:
            continue
        seen.add(file_id)
        distinct.append(path)
    return distinct


def _identity_of(path: Path) -> filewalk.FileIdentity | None:
    try:
        # stat, not lstat: were one path a symlink to the other, following it
        # is what exposes the two as a single file.
        return filewalk.identity(path.stat())
    except OSError:
        return None


def select_deletions(
    groups: list[DuplicateGroup], *, keep: str = "oldest"
) -> tuple[list[Path], list[Skipped]]:
    """For each group, choose one path to keep and return every *other*
    path (across all groups) as the set to delete. Still read-only itself —
    only ``Path.stat()``; the actual delete is the caller's job (see
    ``fclean duplicates --apply``, which quarantines then immediately purges
    these — full deletion, but still audited and deny-list-checked, never a
    raw ``unlink``).

    This is the last check before a permanent delete, so it trusts no one,
    ``find_duplicates`` included: a path is only offered for deletion once
    it is proven to be a different physical file from the kept copy.
    Anything else comes back in the second list, refused, with the reason."""
    if keep not in KEEP_STRATEGIES:
        raise ValueError(f"unknown keep strategy: {keep!r}; expected one of {KEEP_STRATEGIES}")

    def _mtime(path: Path, *, default: float) -> float:
        try:
            return path.stat().st_mtime
        except OSError:
            return default

    to_delete: list[Path] = []
    refused: list[Skipped] = []
    for group in groups:
        if keep == "shortest-path":
            keeper = min(group.paths, key=lambda p: len(str(p)))
        elif keep == "newest":
            keeper = max(group.paths, key=lambda p: _mtime(p, default=float("-inf")))
        else:  # oldest
            keeper = min(group.paths, key=lambda p: _mtime(p, default=float("inf")))

        keeper_id = _identity_of(keeper)
        for path in group.paths:
            if path == keeper:
                continue
            if keeper_id is None:
                reason = f"the copy to keep ({keeper}) can no longer be read, so this may be the last one"
                refused.append(Skipped(path=str(path), reason=reason))
            elif _identity_of(path) == keeper_id:
                reason = f"is the same file as the copy to keep ({keeper}) under another name, not a duplicate"
                refused.append(Skipped(path=str(path), reason=reason))
            else:
                to_delete.append(path)
    return to_delete, refused
