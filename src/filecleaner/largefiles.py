"""Read-only "what is eating my disk" helper: the largest files under a set of roots."""

from __future__ import annotations

import heapq
import os
from collections.abc import Callable
from pathlib import Path
from typing import Any

from filecleaner import config as config_mod
from filecleaner import safety
from filecleaner.models import LargeFile

ProgressCallback = Callable[[str], None]
_PROGRESS_EVERY_DIRS = 500


def find_large_files(
    roots: list[Path],
    config: dict[str, Any],
    *,
    top: int = 30,
    min_size_bytes: int = 0,
    progress: ProgressCallback | None = None,
) -> list[LargeFile]:
    """Return up to ``top`` largest regular files, biggest first.

    Uses a bounded heap so memory stays flat no matter how many files a
    root contains. Symlinks are never followed; protected paths are pruned.
    """
    extra_protected = config_mod.extra_protected_paths(config) + config_mod.data_paths_to_protect(config)
    heap: list[tuple[int, str, float]] = []
    dirs_seen = 0
    for root in roots:
        for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
            dirs_seen += 1
            if progress is not None and dirs_seen % _PROGRESS_EVERY_DIRS == 0:
                progress(f"scanning {dirpath}")
            base = Path(dirpath)
            dirnames[:] = [d for d in dirnames if not safety.is_protected(base / d, extra_protected=extra_protected)]
            for filename in filenames:
                file_path = base / filename
                try:
                    st = os.lstat(file_path)
                except OSError:
                    continue
                if not _is_regular(st.st_mode):
                    continue
                if st.st_size < min_size_bytes:
                    continue
                item = (st.st_size, str(file_path), st.st_mtime)
                if len(heap) < top:
                    heapq.heappush(heap, item)
                elif item > heap[0]:
                    heapq.heapreplace(heap, item)
    ordered = sorted(heap, reverse=True)
    return [LargeFile(path=Path(p), size_bytes=size, mtime=mtime) for size, p, mtime in ordered]


def _is_regular(mode: int) -> bool:
    import stat

    return stat.S_ISREG(mode)
