"""Hardcoded protection rules for paths that must never be touched.

This module is intentionally free of any dependency on user config: the
deny-list here cannot be weakened or overridden by a config file, only
narrowed further (a user can add *more* protected paths, never remove
these). Every candidate is checked here immediately before any
filesystem-mutating action (quarantine move, restore, purge) — and again
at scan time, so protected paths are never even *reported*.
"""

from __future__ import annotations

import threading
import time
import unicodedata
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
    "/private/var/vm",
    "/Applications",
    "/Library/Apple",
    "/Library/CoreServices",
    "/Library/Extensions",
    "/Library/Frameworks",
    "/Library/Keychains",
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

# Personal-data stores under the home directory. No builtin rule targets
# these, but recursive rules (``**/.DS_Store``) walk the whole home dir and
# a custom rule could be written carelessly — so they are denied outright.
HOME_DENY_SUBPATHS: tuple[str, ...] = (
    ".ssh",
    ".gnupg",
    "Library/Keychains",
    "Library/Mail",
    "Library/Messages",
    "Library/Photos",
    "Library/Mobile Documents",
    "Library/Accounts",
    "Library/Passes",
    "Library/Wallet",
)

# Where mounted volumes appear. A constant (rather than a literal inside
# ``_volume_roots``) only so tests can point it at a sandbox.
_VOLUMES_DIR = Path("/Volumes")

_VOLUME_CACHE_TTL_SECONDS = 5.0
_volume_cache: tuple[float, list[Path]] | None = None
_volume_cache_lock = threading.Lock()


def _volume_roots() -> list[Path]:
    """Mounted volume roots, cached briefly: this is called once per
    candidate and ``/Volumes`` does not change between two consecutive
    calls in the same scan. Scanning now walks multiple rules/roots
    concurrently (see ``scanner._run_targets``), so this can be called from
    several threads at once — the lock keeps the cache's read-check-write
    from racing."""
    global _volume_cache
    with _volume_cache_lock:
        now = time.monotonic()
        if _volume_cache is not None and now - _volume_cache[0] < _VOLUME_CACHE_TTL_SECONDS:
            return _volume_cache[1]

        roots = [Path("/")]
        volumes = _VOLUMES_DIR
        if volumes.is_dir():
            try:
                for entry in volumes.iterdir():
                    if entry.is_dir() or entry.is_symlink():
                        roots.append(entry)
            except OSError:
                pass
        _volume_cache = (now, roots)
        return roots


def reset_caches() -> None:
    """Forget cached mount information (tests, or after a volume change)."""
    global _volume_cache
    with _volume_cache_lock:
        _volume_cache = None


def _self_protected_paths() -> list[Path]:
    """Paths belonging to File Cleaner itself: never let it quarantine its own code."""
    here = Path(__file__).resolve().parent
    return [here]


def _resolve(path: Path) -> Path:
    try:
        return path.resolve(strict=False)
    except (OSError, RuntimeError):
        return path.absolute()


def _is_under(path: Path, ancestor: Path) -> bool:
    return path == ancestor or ancestor in path.parents


def _key(path: str) -> str:
    """Canonical comparison key for a path string.

    APFS (like HFS+ before it) is case-insensitive and normalisation-
    insensitive by default, and ``Path.resolve()`` rewrites a component only
    when it is a symlink — so ``/system``, ``~/.SSH`` or an NFD-spelled home
    directory reach the real protected directories while comparing unequal
    to the deny-list as written. Both sides of every deny comparison go
    through this key instead: Unicode canonical caseless matching,
    NFD(casefold(NFD(s))).

    Folding is unconditional, even on a case-sensitive volume, where it can
    only ever protect *more* (``/Volumes/X/system`` as well as ``System``).
    """
    if path.isascii():
        return path.casefold()
    return unicodedata.normalize("NFD", unicodedata.normalize("NFD", path).casefold())


def _key_is_under(key: str, deny_key: str) -> bool:
    # The separator is part of the test so that ``/usr2`` is not under ``/usr``.
    return key == deny_key or key.startswith(deny_key.rstrip("/") + "/")


def is_protected(path: Path, *, extra_protected: tuple[Path, ...] = ()) -> bool:
    """Return True if ``path`` must never be moved, restored into, or purged."""
    try:
        resolved = path.resolve(strict=False)
    except (OSError, RuntimeError):
        return True  # cannot be resolved, so cannot be shown to be safe
    key = _key(str(resolved))

    for deny in ABSOLUTE_DENY_PATHS:
        if _key_is_under(key, _key(deny)):
            return True

    for root in _volume_roots():
        root_key = _key(str(_resolve(root))).rstrip("/")
        for sub in RELATIVE_DENY_SUBPATHS:
            if _key_is_under(key, f"{root_key}/{_key(sub)}"):
                return True

    home_key = _key(str(_resolve(Path.home())))
    if key == home_key:
        return True  # never quarantine the home directory itself
    for sub in HOME_DENY_SUBPATHS:
        if _key_is_under(key, f"{home_key}/{_key(sub)}"):
            return True

    for self_path in _self_protected_paths():
        if _key_is_under(key, _key(str(self_path))):
            return True

    return any(_key_is_under(key, _key(str(_resolve(extra)))) for extra in extra_protected)


def is_within_allowed_roots(path: Path, allowed_roots: tuple[Path, ...]) -> bool:
    """Defense in depth: a candidate must live under one of the roots that
    were actually scanned, never somewhere the scanner never visited."""
    resolved = _resolve(path)
    return any(_is_under(resolved, _resolve(root)) for root in allowed_roots)
