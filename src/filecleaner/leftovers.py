"""Two specific kinds of "installation residue" scanning's glob-based rules
can't express, since both need to cross-reference *other* filesystem state
(what's actually installed) rather than matching a fixed path pattern:

1. **Orphaned app-support folders**: subfolders under ``~/Library/{Application
   Support,Caches,Preferences,...}`` whose owning app is no longer in
   ``/Applications``. Folder-naming heuristics have real false-positive
   potential (a Mac App Store sandbox container, a CLI tool with no ``.app``
   bundle) — this is why results are risk ``"high"`` and callers should treat
   it as opt-in, same spirit as the opt-in rules in ``rules.py``.
2. **Installer archive cleanup**: ``.dmg``/``.pkg``/``.zip`` files in
   Downloads whose apparent product already exists — either an installed
   ``.app`` with a matching name, or an already-extracted sibling folder
   next to the archive.

Both are read-only: they return ``Candidate`` objects, exactly like
``scanner.run_scan``, so callers act on them through the normal
``quarantine_candidates``/``purge_entries`` flow — nothing here ever
touches the filesystem.
"""

from __future__ import annotations

import os
import time
from pathlib import Path
from typing import Any

from filecleaner import config as config_mod
from filecleaner import listing, plists, safety
from filecleaner.models import Candidate
from filecleaner.scanner import dir_stats_many

_LIBRARY_SUBDIRS = (
    "Application Support",
    "Caches",
    "Preferences",
    "Logs",
    "Saved Application State",
    "Containers",
    "HTTPStorages",
)
_APPLICATIONS_DIRS = (Path("/Applications"), Path.home() / "Applications")
_INSTALLER_EXTENSIONS = (".dmg", ".pkg", ".zip")
_APP_LEFTOVERS_CATEGORY = "App leftovers (opt-in)"
_INSTALLER_CLEANUP_CATEGORY = "Installer cleanup (opt-in)"


def installed_apps() -> tuple[set[str], set[str]]:
    """(bundle_ids, display_names) for every ``.app`` under ``/Applications``
    and ``~/Applications`` — the reference set both detectors match against."""
    bundle_ids: set[str] = set()
    names: set[str] = set()
    for apps_dir in _APPLICATIONS_DIRS:
        try:
            entries = list(apps_dir.iterdir())
        except OSError:
            continue
        for entry in entries:
            if entry.suffix != ".app":
                continue
            names.add(entry.stem)
            bundle_id = plists.load_dict(entry / "Contents" / "Info.plist").get("CFBundleIdentifier")
            if isinstance(bundle_id, str):
                bundle_ids.add(bundle_id)
    return bundle_ids, names


def _looks_installed(name: str, bundle_ids: set[str], names: set[str]) -> bool:
    if name in bundle_ids or name in names:
        return True
    # Many Library subfolders are named after the bundle id with extra
    # suffixes, e.g. "com.example.app.savedState" — match on prefix too.
    return any(name.startswith(bid) for bid in bundle_ids)


def find_app_leftovers(
    config: dict[str, Any], *, home: Path | None = None, min_age_days: int = 30
) -> list[Candidate]:
    """Subfolders under ``~/Library/{Application Support,Caches,...}`` whose
    name matches no currently-installed app. Opt-in, high risk."""
    home = home or Path.home()
    bundle_ids, names = installed_apps()
    extra_protected = config_mod.extra_protected_paths(config) + config_mod.data_paths_to_protect(config)
    now = time.time()

    orphans: list[tuple[Path, os.stat_result, bool]] = []
    for subdir_name in _LIBRARY_SUBDIRS:
        base = home / "Library" / subdir_name
        try:
            # Containers is where macOS interrupts listings (see ``listing``).
            entries = [base / entry.name for entry in listing.list_dir(str(base))]
        except OSError:
            continue
        for entry in entries:
            if entry.is_symlink() or safety.is_protected(entry, extra_protected=extra_protected):
                continue
            if _looks_installed(entry.name, bundle_ids, names):
                continue
            try:
                st = entry.lstat()
            except OSError:
                continue
            orphans.append((entry, st, entry.is_dir()))

    # Sizing the folders is nearly all of the work (a thousand of them, some
    # huge), so it is done in one batch that the native helper can spread out.
    sized = iter(dir_stats_many([entry for entry, _st, is_dir in orphans if is_dir]))
    candidates: list[Candidate] = []
    for entry, st, is_dir in orphans:
        if is_dir:
            size, newest = next(sized)
            mtime = max(st.st_mtime, newest)
        else:
            size, mtime = st.st_size, st.st_mtime
        if (now - mtime) / 86400 < min_age_days:
            continue
        candidates.append(
            Candidate(
                path=entry,
                size_bytes=size,
                is_dir=is_dir,
                mtime=mtime,
                rule_id="app_leftovers",
                category=_APP_LEFTOVERS_CATEGORY,
                risk="high",
            )
        )
    return candidates

def find_installer_cleanup(config: dict[str, Any], *, downloads: Path | None = None) -> list[Candidate]:
    """``.dmg``/``.pkg``/``.zip`` files in Downloads whose apparent product
    already exists (a matching-name installed ``.app``, or an
    already-extracted sibling folder). Opt-in, medium risk."""
    downloads = downloads or (Path.home() / "Downloads")
    bundle_ids, names = installed_apps()
    extra_protected = config_mod.extra_protected_paths(config) + config_mod.data_paths_to_protect(config)
    candidates: list[Candidate] = []

    try:
        entries = list(downloads.iterdir())
    except OSError:
        return []

    for entry in entries:
        if entry.is_symlink() or not entry.is_file():
            continue
        if entry.suffix.lower() not in _INSTALLER_EXTENSIONS:
            continue
        if safety.is_protected(entry, extra_protected=extra_protected):
            continue
        stem = entry.stem
        already_installed = stem in names or any(bid.rsplit(".", 1)[-1].lower() == stem.lower() for bid in bundle_ids)
        already_extracted = (downloads / stem).is_dir()
        if not (already_installed or already_extracted):
            continue
        try:
            st = entry.stat()
        except OSError:
            continue
        candidates.append(
            Candidate(
                path=entry,
                size_bytes=st.st_size,
                is_dir=False,
                mtime=st.st_mtime,
                rule_id="installer_cleanup",
                category=_INSTALLER_CLEANUP_CATEGORY,
                risk="medium",
            )
        )
    return candidates
