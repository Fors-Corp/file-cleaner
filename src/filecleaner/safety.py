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
from dataclasses import dataclass
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

# How long a built deny index is trusted. Everything in it is fixed for the
# life of a process except the set of mounted volumes, so this is really
# "how soon is a newly mounted volume noticed".
_DENY_INDEX_TTL_SECONDS = 5.0


def _volume_roots() -> list[Path]:
    """Currently mounted volume roots."""
    roots = [Path("/")]
    volumes = _VOLUMES_DIR
    if volumes.is_dir():
        try:
            for entry in volumes.iterdir():
                if entry.is_dir() or entry.is_symlink():
                    roots.append(entry)
        except OSError:
            pass
    return roots


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


@dataclass(frozen=True)
class _DenyIndex:
    """Every deny rule — absolute, per-volume, per-home, self, user config —
    flattened to canonical keys, so a check is two string operations."""

    home: str  # protected as itself only; its children are fair game
    prefixes: tuple[str, ...]  # each ends with "/": protected at or below

    def covers(self, key: str) -> bool:
        # The trailing separator is part of the test so that ``/usr2`` is
        # not under ``/usr``, while ``/usr`` itself still is.
        return key == self.home or (key + "/").startswith(self.prefixes)


def _build_deny_index(extra_protected: tuple[Path, ...]) -> _DenyIndex:
    # Candidates are compared in resolved form, so every deny directory is
    # indexed in resolved form too (``/etc`` is really ``/private/etc``).
    denied: list[Path] = []
    for deny in ABSOLUTE_DENY_PATHS:
        denied += [Path(deny), _resolve(Path(deny))]
    for root in _volume_roots():
        resolved_root = _resolve(root)
        denied += [resolved_root / sub for sub in RELATIVE_DENY_SUBPATHS]
    home = _resolve(Path.home())
    denied += [home / sub for sub in HOME_DENY_SUBPATHS]
    denied += _self_protected_paths()
    denied += [_resolve(extra) for extra in extra_protected]

    prefixes = {_key(str(path)).rstrip("/") + "/" for path in denied}
    return _DenyIndex(home=_key(str(home)), prefixes=tuple(sorted(prefixes)))


_index_cache: dict[tuple[Path, ...], tuple[float, _DenyIndex]] = {}
_index_cache_lock = threading.Lock()


def _deny_index(extra_protected: tuple[Path, ...]) -> _DenyIndex:
    """The deny index for this ``extra_protected``, rebuilt at most once per
    TTL. This sits on the scanner's per-entry hot path, and scanning walks
    several rules concurrently (see ``scanner._run_targets``): a fresh entry
    is returned without taking the lock, and the lock only serialises
    rebuilds so an expiry does not make every thread rebuild at once."""
    now = time.monotonic()
    cached = _index_cache.get(extra_protected)
    if cached is not None and now - cached[0] < _DENY_INDEX_TTL_SECONDS:
        return cached[1]
    with _index_cache_lock:
        cached = _index_cache.get(extra_protected)
        if cached is not None and now - cached[0] < _DENY_INDEX_TTL_SECONDS:
            return cached[1]
        index = _build_deny_index(extra_protected)
        for stale in [k for k, (built, _) in _index_cache.items() if now - built >= _DENY_INDEX_TTL_SECONDS]:
            del _index_cache[stale]
        _index_cache[extra_protected] = (now, index)
        return index


def reset_caches() -> None:
    """Forget the cached deny index (tests, or after a volume change)."""
    with _index_cache_lock:
        _index_cache.clear()


def is_protected(path: Path, *, extra_protected: tuple[Path, ...] = ()) -> bool:
    """Return True if ``path`` must never be moved, restored into, or purged.

    This is the authoritative check: it resolves every symlink in ``path``
    first, so it is safe on arbitrary input (a hand-edited plan, a custom
    rule, a user-supplied root)."""
    try:
        resolved = path.resolve(strict=False)
    except (OSError, RuntimeError):
        return True  # cannot be resolved, so cannot be shown to be safe
    return _deny_index(extra_protected).covers(_key(str(resolved)))


def is_protected_resolved(resolved: str, *, extra_protected: tuple[Path, ...] = ()) -> bool:
    """``is_protected`` for a path the caller guarantees is already fully
    resolved — no filesystem access at all.

    Only for a directory walk that resolved its start directory and skips
    symlinked entries, where ``resolved_dir + "/" + name`` is resolved by
    construction. Never a substitute for ``is_protected`` in front of a
    filesystem-mutating action."""
    return _deny_index(extra_protected).covers(_key(resolved))


def deny_index_keys(extra_protected: tuple[Path, ...] = ()) -> tuple[str, tuple[str, ...]]:
    """The current deny index as plain data: (home key, prefix keys).

    For an out-of-process walker to *prune* with. It is a snapshot and a
    convenience, not a delegation: whatever such a walker reports must still
    go through ``is_protected`` here before it is used."""
    index = _deny_index(extra_protected)
    return index.home, index.prefixes


def is_within_allowed_roots(path: Path, allowed_roots: tuple[Path, ...]) -> bool:
    """Defense in depth: a candidate must live under one of the roots that
    were actually scanned, never somewhere the scanner never visited."""
    resolved = _resolve(path)
    return any(_is_under(resolved, _resolve(root)) for root in allowed_roots)
