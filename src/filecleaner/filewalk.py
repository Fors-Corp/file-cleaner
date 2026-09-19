"""Walk a set of roots, visiting each physical file exactly once.

One file can be reached by more than one path: overlapping roots, a root
spelled in another case or Unicode normalisation form on a filesystem that
ignores both, a root that is a symlink into another root, or a second hard
link. Anything that adds files up or compares them with each other must not
count one file twice — ``fclean duplicates --apply`` would otherwise
"de-duplicate" a file against itself and permanently delete the only copy.

Files are told apart by ``(st_dev, st_ino)``, the filesystem's own identity
for a file, never by comparing path strings: no normalisation of a path can
be trusted to agree with what the filesystem itself considers equal
(``Path.resolve()``, for one, leaves case alone).
"""

from __future__ import annotations

import os
import stat
from collections.abc import Iterator
from pathlib import Path
from typing import NamedTuple

from filecleaner import native_walk, safety

FileIdentity = tuple[int, int]


class FileStat(NamedTuple):
    """The two facts callers need about a file, under ``os.stat_result``'s
    names for them."""

    st_size: int
    st_mtime: float


def identity(st: os.stat_result) -> FileIdentity:
    return (st.st_dev, st.st_ino)


def _walk_natively(
    roots: list[Path], extra_protected: tuple[Path, ...], min_size: int
) -> list[tuple[Path, FileStat]] | None:
    """The same walk, done by the native helper (see ``native_walk``). None
    when there is no helper or it failed, and the caller walks in Python.

    The helper is an accelerator, not an authority, so what it reports is
    checked here: a file must lie under the root it claims, and the deny-list
    is applied again in Python rather than taken on trust. (The helper never
    follows a symlink below a root, so a file's resolved path is its root's
    resolved path plus the rest — which is what lets that re-check run with
    no filesystem access, 860k files in well under a second.) Telling two
    *names of one file* apart is NOT delegated at all where it matters: see
    ``duplicates.find_duplicates`` and ``duplicates.select_deletions``."""
    deny_home, deny_prefixes = safety.deny_index_keys(extra_protected)
    spelled = [str(root) for root in roots]
    found = native_walk.files(spelled, min_size=min_size, deny_home=deny_home, deny_prefixes=deny_prefixes)
    if found is None:
        return None
    resolved = [os.path.realpath(root).rstrip("/") for root in spelled]
    inside = [root.rstrip("/") + "/" for root in spelled]
    checked: list[tuple[Path, FileStat]] = []
    for item in found:
        if not item.path.startswith(inside[item.root]) or item.size < min_size:
            continue
        resolved_path = resolved[item.root] + "/" + item.path[len(inside[item.root]) :]
        if safety.is_protected_resolved(resolved_path, extra_protected=extra_protected):
            continue
        checked.append((Path(item.path), FileStat(item.size, item.mtime)))
    return checked


def walk_unique_files(
    roots: list[Path], *, extra_protected: tuple[Path, ...] = (), min_size: int = 0
) -> Iterator[tuple[Path, FileStat]]:
    """Yield ``(path, FileStat)`` for every regular file of at least
    ``min_size`` bytes under ``roots``, once per physical file. Symlinks are
    never followed and protected directories are pruned.

    Which of a hard-linked file's names is reported is unspecified (the
    Python walk gives the first it meets, the native helper the smallest).

    A file with a single link lives in exactly one directory, so it can only
    be reached twice by visiting that directory twice: remembering the
    directories visited is enough, and also stops an aliased or overlapping
    root from being walked a second time. Only hard-linked files need
    remembering one by one, which keeps memory flat in the number of files.

    A filesystem that reports no inode numbers collapses to one identity per
    device here, which under-reports files rather than double-counting them.
    """
    native = _walk_natively(roots, extra_protected, min_size)
    if native is not None:
        yield from native
        return

    seen_dirs: set[FileIdentity] = set()
    seen_hard_links: set[FileIdentity] = set()
    for root in roots:
        for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
            try:
                # stat, not lstat: a root may itself be a symlink to a directory.
                dir_id = identity(os.stat(dirpath))
            except OSError:
                dirnames[:] = []
                continue
            if dir_id in seen_dirs:
                dirnames[:] = []
                continue
            seen_dirs.add(dir_id)

            base = Path(dirpath)
            dirnames[:] = [d for d in dirnames if not safety.is_protected(base / d, extra_protected=extra_protected)]
            for filename in filenames:
                file_path = base / filename
                try:
                    st = os.lstat(file_path)
                except OSError:
                    continue
                if not stat.S_ISREG(st.st_mode):
                    continue
                if st.st_nlink > 1:
                    file_id = identity(st)
                    if file_id in seen_hard_links:
                        continue
                    seen_hard_links.add(file_id)
                if st.st_size >= min_size:
                    yield file_path, FileStat(st.st_size, st.st_mtime)
