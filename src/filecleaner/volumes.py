"""Detect the boot volume plus any mounted external/removable drives.

Only local filesystem enumeration — no network calls.
"""

from __future__ import annotations

import shutil
from pathlib import Path

from filecleaner.models import VolumeInfo


def list_volumes() -> list[VolumeInfo]:
    volumes: list[VolumeInfo] = []
    seen_devices: set[int] = set()

    root = Path("/")
    root_usage = shutil.disk_usage(root)
    root_dev = root.stat().st_dev
    seen_devices.add(root_dev)
    volumes.append(
        VolumeInfo(
            name="Macintosh HD",
            path=root,
            total_bytes=root_usage.total,
            used_bytes=root_usage.used,
            free_bytes=root_usage.free,
            is_root=True,
        )
    )

    volumes_dir = Path("/Volumes")
    if volumes_dir.is_dir():
        for entry in sorted(volumes_dir.iterdir(), key=lambda p: p.name):
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


def default_scan_roots(configured: list[str]) -> list[Path]:
    """Resolve the roots to scan: explicit config wins, otherwise home dir
    plus every detected external volume (the boot volume is scanned via the
    home directory + builtin system-cache rules, not by walking `/` itself)."""
    if configured:
        return [Path(p).expanduser() for p in configured]

    roots = [Path.home()]
    for vol in list_volumes():
        if not vol.is_root:
            roots.append(vol.path)
    return roots
