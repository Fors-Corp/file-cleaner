"""Read-only "what is eating my disk" helper: the largest files under a set of roots."""

from __future__ import annotations

import heapq
from collections.abc import Callable
from pathlib import Path
from typing import Any

from filecleaner import config as config_mod
from filecleaner import filewalk
from filecleaner.models import LargeFile

ProgressCallback = Callable[[str], None]
_PROGRESS_EVERY_FILES = 5000


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
    Each physical file is listed once, however many paths or hard links
    lead to it (see ``filewalk``), so the space it uses is never counted twice.
    """
    extra_protected = config_mod.extra_protected_paths(config) + config_mod.data_paths_to_protect(config)
    heap: list[tuple[int, str, float]] = []
    files_seen = 0
    for file_path, st in filewalk.walk_unique_files(roots, extra_protected=extra_protected):
        files_seen += 1
        if progress is not None and files_seen % _PROGRESS_EVERY_FILES == 0:
            progress(f"scanning {file_path.parent}")
        if st.st_size < min_size_bytes:
            continue
        item = (st.st_size, str(file_path), st.st_mtime)
        if len(heap) < top:
            heapq.heappush(heap, item)
        elif item > heap[0]:
            heapq.heapreplace(heap, item)
    ordered = sorted(heap, reverse=True)
    return [LargeFile(path=Path(p), size_bytes=size, mtime=mtime) for size, p, mtime in ordered]
