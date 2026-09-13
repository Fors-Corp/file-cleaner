"""Hash-based duplicate file finder.

Read-only: never moves or modifies anything. Files are only ever hashed
(never printed or logged with their contents) — hashing is a three-stage
funnel (size -> partial hash -> full hash) so most non-duplicate files are
ruled out without ever being fully read.
"""

from __future__ import annotations

import hashlib
import os
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

from filecleaner import config as config_mod
from filecleaner import safety
from filecleaner.models import DuplicateGroup

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
    extra_protected = config_mod.extra_protected_paths(config) + config_mod.data_paths_to_protect(config)
    max_hash_bytes = config.get("hash_duplicates_max_bytes", 2_000_000_000)

    size_buckets: dict[int, list[Path]] = {}
    files_seen = 0
    for root in roots:
        for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
            base = Path(dirpath)
            dirnames[:] = [
                d for d in dirnames if not safety.is_protected(base / d, extra_protected=extra_protected)
            ]
            for filename in filenames:
                file_path = base / filename
                try:
                    if file_path.is_symlink():
                        continue
                    size = file_path.stat().st_size
                except OSError:
                    continue
                files_seen += 1
                if progress is not None and files_seen % _PROGRESS_EVERY_FILES == 0:
                    progress(f"scanned {files_seen} files, comparing sizes…")
                if size < min_size_bytes:
                    continue
                if safety.is_protected(file_path, extra_protected=extra_protected):
                    continue
                size_buckets.setdefault(size, []).append(file_path)

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
            if len(group_paths) > 1:
                groups.append(DuplicateGroup(sha256=full_hash, size_bytes=size, paths=sorted(group_paths)))

    groups.sort(key=lambda g: (g.wasted_bytes, g.sha256), reverse=True)
    if max_groups:
        groups = groups[:max_groups]
    return groups
