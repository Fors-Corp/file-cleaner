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

from filecleaner import safety

FileIdentity = tuple[int, int]


def identity(st: os.stat_result) -> FileIdentity:
    return (st.st_dev, st.st_ino)


def walk_unique_files(
    roots: list[Path], *, extra_protected: tuple[Path, ...] = ()
) -> Iterator[tuple[Path, os.stat_result]]:
    """Yield ``(path, lstat result)`` for every regular file under ``roots``,
    once per physical file, under the first path that reaches it. Symlinks
    are never followed and protected directories are pruned.

    A file with a single link lives in exactly one directory, so it can only
    be reached twice by visiting that directory twice: remembering the
    directories visited is enough, and also stops an aliased or overlapping
    root from being walked a second time. Only hard-linked files need
    remembering one by one, which keeps memory flat in the number of files.

    A filesystem that reports no inode numbers collapses to one identity per
    device here, which under-reports files rather than double-counting them.
    """
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
                yield file_path, st
