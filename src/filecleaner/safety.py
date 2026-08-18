"""Hardcoded protection rules for paths that must never be touched.

This module is intentionally free of any dependency on user config: the
deny-list here cannot be weakened or overridden by a config file, only
narrowed further (a user can add *more* protected paths, never remove
these). Every candidate is checked here immediately before any
filesystem-mutating action (quarantine move, restore, purge).
"""

from __future__ import annotations

from pathlib import Path

# Absolute paths (on the boot volume) that are always off-limits, no matter
# what rule matched them.
ABSOLUTE_DENY_PATHS: tuple[str, ...] = (
    "/System",
    "/usr",
    "/bin",
    "/sbin",
    "/etc",
    "/dev",
    "/private/etc",
    "/private/var/db",
    "/private/var/root",
    "/private/var/audit",
    "/Applications",
    "/Library/Apple",
    "/Library/CoreServices",
    "/Library/Extensions",
    "/Library/Frameworks",
    "/Library/StagedExtensions",
    "/Library/SystemMigration",
)

# Subpaths that are dangerous under *any* volume root (the boot volume, or
# any external/removable drive that also happens to be bootable / have its
# own OS layout).
RELATIVE_DENY_SUBPATHS: tuple[str, ...] = (
    "System",
    "usr",
    "bin",
    "sbin",
    "private/var/db",
    "Library/Apple",
    "Library/CoreServices",
)


def _volume_roots() -> list[Path]:
    roots = [Path("/")]
    volumes = Path("/Volumes")
    if volumes.is_dir():
        try:
            for entry in volumes.iterdir():
                if entry.is_dir() or entry.is_symlink():
                    roots.append(entry)
        except OSError:
            pass
    return roots


def _self_protected_paths() -> list[Path]:
    """Paths belonging to filecleaner itself: never let it quarantine its own code."""
    here = Path(__file__).resolve().parent
    return [here]


def is_protected(path: Path, *, extra_protected: tuple[Path, ...] = ()) -> bool:
    """Return True if `path` must never be moved, restored into, or purged."""
    try:
        resolved = path.resolve(strict=False)
    except OSError:
        resolved = path.absolute()

    for deny in ABSOLUTE_DENY_PATHS:
        deny_path = Path(deny)
        if resolved == deny_path or deny_path in resolved.parents:
            return True

    for root in _volume_roots():
        try:
            rel = resolved.relative_to(root.resolve(strict=False))
        except (OSError, ValueError):
            continue
        rel_str = str(rel)
        for sub in RELATIVE_DENY_SUBPATHS:
            if rel_str == sub or rel_str.startswith(sub + "/"):
                return True

    for self_path in _self_protected_paths():
        if resolved == self_path or self_path in resolved.parents:
            return True

    for extra in extra_protected:
        try:
            extra_resolved = extra.resolve(strict=False)
        except OSError:
            extra_resolved = extra.absolute()
        if resolved == extra_resolved or extra_resolved in resolved.parents:
            return True

    return False


def is_within_allowed_roots(path: Path, allowed_roots: tuple[Path, ...]) -> bool:
    """Defense in depth: a candidate must live under one of the roots that
    were actually scanned, never somewhere the scanner never visited."""
    try:
        resolved = path.resolve(strict=False)
    except OSError:
        resolved = path.absolute()
    for root in allowed_roots:
        try:
            root_resolved = root.resolve(strict=False)
        except OSError:
            root_resolved = root.absolute()
        if resolved == root_resolved or root_resolved in resolved.parents:
            return True
    return False
