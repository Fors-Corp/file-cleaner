"""Detect the boot volume plus any mounted external/removable drives.

Only local filesystem enumeration — no network calls. Works on any POSIX
system; the ``/Volumes`` conventions are macOS-specific and simply yield
nothing elsewhere.
"""

from __future__ import annotations

import os
import shutil
import sys
from pathlib import Path

from filecleaner.models import VolumeInfo

VOLUMES_DIR = Path("/Volumes")


def _root_volume_name() -> str:
    """The boot volume's user-visible name.

    On macOS the boot volume is aliased under ``/Volumes/<Name>`` (same
    device number as ``/``); reading it there gives the real name instead
    of assuming "Macintosh HD".
    """
    fallback = "Macintosh HD" if sys.platform == "darwin" else "/"
    try:
        root_dev = Path("/").stat().st_dev
    except OSError:
        return fallback
    if not VOLUMES_DIR.is_dir():
        return fallback
    try:
        for entry in VOLUMES_DIR.iterdir():
            try:
                if entry.stat().st_dev == root_dev:
                    return entry.name
            except OSError:
                continue
    except OSError:
        pass
    return fallback


def list_volumes() -> list[VolumeInfo]:
    volumes: list[VolumeInfo] = []
    seen_devices: set[int] = set()

    root = Path("/")
    root_usage = shutil.disk_usage(root)
    root_dev = root.stat().st_dev
    seen_devices.add(root_dev)
    volumes.append(
        VolumeInfo(
            name=_root_volume_name(),
            path=root,
            total_bytes=root_usage.total,
            used_bytes=root_usage.used,
            free_bytes=root_usage.free,
            is_root=True,
        )
    )

    if VOLUMES_DIR.is_dir():
        try:
            entries = sorted(VOLUMES_DIR.iterdir(), key=lambda p: p.name)
        except OSError:
            entries = []
        for entry in entries:
            try:
                st = entry.stat()
            except OSError:
                continue
            if st.st_dev in seen_devices:
                # Same underlying device as one already listed (e.g. the
                # root volume also appears aliased under /Volumes).
                continue
            seen_devices.add(st.st_dev)
            try:
                usage = shutil.disk_usage(entry)
            except OSError:
                continue
            volumes.append(
                VolumeInfo(
                    name=entry.name,
                    path=entry,
                    total_bytes=usage.total,
                    used_bytes=usage.used,
                    free_bytes=usage.free,
                    is_root=False,
                )
            )

    return volumes


def mount_point_for(path: Path) -> Path:
    """Return the mount point of the filesystem containing ``path``.

    Walks upward until the device number changes. Works for paths that do
    not exist yet by starting from the nearest existing ancestor.
    """
    current = path.absolute()
    while not current.exists() and current.parent != current:
        current = current.parent
    try:
        dev = os.lstat(current).st_dev
    except OSError:
        return Path("/")
    while current.parent != current:
        try:
            if os.lstat(current.parent).st_dev != dev:
                return current
        except OSError:
            return current
        current = current.parent
    return current


def same_filesystem(a: Path, b: Path) -> bool:
    return mount_point_for(a) == mount_point_for(b)


def default_scan_roots(configured: list[str]) -> list[Path]:
    """Resolve the roots to scan: explicit config wins, otherwise home dir
    plus every detected external volume (the boot volume is scanned via the
    home directory + builtin system-cache rules, not by walking ``/`` itself)."""
    if configured:
        return [Path(p).expanduser() for p in configured]

    roots = [Path.home()]
    for vol in list_volumes():
        if not vol.is_root:
            roots.append(vol.path)
    return roots
