"""iPhone/iPad backup management.

These are ordinary files sitting on the Mac's own disk under
~/Library/Application Support/MobileSync/Backup/<UDID>/ — created whenever
an iOS device backs up to this computer via Finder/cable. They're often
20-100GB+ each and pile up over time. This module only reads Info.plist /
Manifest.plist metadata (device name, date, encryption flag) — never the
backed-up data itself — and reuses the same quarantine pipeline as
everything else, so removing a stale backup is fully restorable.

Note: this directory is TCC-protected on macOS. Enumerating it without
Full Disk Access raises BackupAccessDenied.
"""

from __future__ import annotations

import plistlib
from datetime import datetime, timezone
from pathlib import Path

from filecleaner.models import BackupInfo, Candidate

DEFAULT_BACKUP_ROOT = Path.home() / "Library" / "Application Support" / "MobileSync" / "Backup"


class BackupAccessDenied(Exception):
    """Raised when macOS's privacy protection (TCC) blocks reading the backup directory."""


def _dir_size(path: Path) -> int:
    total = 0
    try:
        for entry in path.rglob("*"):
            try:
                if entry.is_file() and not entry.is_symlink():
                    total += entry.stat().st_size
            except OSError:
                continue
    except OSError:
        pass
    return total


def _load_plist(path: Path) -> dict:
    try:
        with path.open("rb") as f:
            return plistlib.load(f)
    except (OSError, plistlib.InvalidFileException):
        return {}


def find_backups(base: Path | None = None) -> list[BackupInfo]:
    base = base or DEFAULT_BACKUP_ROOT
    if not base.is_dir():
        return []

    try:
        entries = list(base.iterdir())
    except PermissionError as exc:
        raise BackupAccessDenied(
            "Can't read the iPhone/iPad backup folder — macOS is blocking access. "
            "Grant Full Disk Access to your terminal app in System Settings -> "
            "Privacy & Security -> Full Disk Access, then try again."
        ) from exc

    backups: list[BackupInfo] = []
    for entry in entries:
        if not entry.is_dir():
            continue
        info = _load_plist(entry / "Info.plist")
        manifest = _load_plist(entry / "Manifest.plist")

        device_name = info.get("Device Name") or entry.name
        product_type = info.get("Product Type", "")
        last_backup_date = info.get("Last Backup Date")
        if not isinstance(last_backup_date, datetime):
            last_backup_date = None
        encrypted = bool(manifest.get("IsEncrypted", False))

        backups.append(
            BackupInfo(
                udid=entry.name,
                path=entry,
                device_name=device_name,
                product_type=product_type,
                last_backup_date=last_backup_date,
                size_bytes=_dir_size(entry),
                encrypted=encrypted,
            )
        )
    return backups


def _age_days(dt: datetime | None) -> float | None:
    if dt is None:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return (datetime.now(timezone.utc) - dt).total_seconds() / 86400


def stale_backups(
    backups: list[BackupInfo],
    *,
    keep_latest_per_device: int = 1,
    older_than_days: int | None = None,
) -> list[BackupInfo]:
    """Backups eligible for cleanup: always keeps the N most recent backups
    per device name, and (if given) only among those older than a threshold."""
    grouped: dict[str, list[BackupInfo]] = {}
    for backup in backups:
        grouped.setdefault(backup.device_name, []).append(backup)

    stale: list[BackupInfo] = []
    for group in grouped.values():
        group_sorted = sorted(
            group,
            key=lambda b: b.last_backup_date or datetime.min.replace(tzinfo=timezone.utc),
            reverse=True,
        )
        candidates = group_sorted[keep_latest_per_device:]
        for backup in candidates:
            if older_than_days is not None:
                age = _age_days(backup.last_backup_date)
                if age is None or age < older_than_days:
                    continue
            stale.append(backup)
    return stale


def to_candidate(backup: BackupInfo) -> Candidate:
    """Wrap a backup as a Candidate so it can flow through the same
    quarantine/restore/purge pipeline as everything else."""
    return Candidate(
        path=backup.path,
        size_bytes=backup.size_bytes,
        is_dir=True,
        mtime=backup.last_backup_date.timestamp() if backup.last_backup_date else 0.0,
        rule_id="iphone_backup",
        category="Device Backups",
        risk="medium",
    )
