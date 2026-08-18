import plistlib
from datetime import datetime, timedelta, timezone

import pytest

from filecleaner import backups


def _make_backup(root, udid, device_name, product_type, days_ago, encrypted=False):
    backup_dir = root / udid
    backup_dir.mkdir(parents=True)
    info = {
        "Device Name": device_name,
        "Product Type": product_type,
        "Last Backup Date": datetime.now(timezone.utc) - timedelta(days=days_ago),
    }
    with (backup_dir / "Info.plist").open("wb") as f:
        plistlib.dump(info, f)
    if encrypted:
        with (backup_dir / "Manifest.plist").open("wb") as f:
            plistlib.dump({"IsEncrypted": True}, f)
    (backup_dir / "payload.bin").write_bytes(b"x" * 2048)
    return backup_dir


def test_find_backups_parses_metadata(tmp_path):
    root = tmp_path / "Backup"
    _make_backup(root, "udid-1", "iPhone A", "iPhone14,2", days_ago=5)
    _make_backup(root, "udid-2", "iPad B", "iPad13,1", days_ago=2, encrypted=True)

    found = backups.find_backups(base=root)

    assert len(found) == 2
    by_name = {b.device_name: b for b in found}
    assert by_name["iPhone A"].product_type == "iPhone14,2"
    assert by_name["iPad B"].encrypted is True
    assert by_name["iPhone A"].encrypted is False
    assert by_name["iPhone A"].size_bytes >= 2048


def test_find_backups_missing_dir_returns_empty(tmp_path):
    assert backups.find_backups(base=tmp_path / "does_not_exist") == []


def test_find_backups_permission_denied_raises(tmp_path):
    root = tmp_path / "Backup"
    root.mkdir()
    _make_backup(root, "udid-1", "iPhone A", "iPhone14,2", days_ago=5)
    root.chmod(0o000)
    try:
        with pytest.raises(backups.BackupAccessDenied):
            backups.find_backups(base=root)
    finally:
        root.chmod(0o755)


def test_stale_backups_keeps_latest_per_device(tmp_path):
    root = tmp_path / "Backup"
    _make_backup(root, "udid-1", "iPhone A", "iPhone14,2", days_ago=5)
    _make_backup(root, "udid-2", "iPhone A", "iPhone14,2", days_ago=40)
    _make_backup(root, "udid-3", "iPad B", "iPad13,1", days_ago=2)

    found = backups.find_backups(base=root)
    stale = backups.stale_backups(found, keep_latest_per_device=1)

    assert len(stale) == 1
    assert stale[0].udid == "udid-2"


def test_stale_backups_respects_older_than(tmp_path):
    root = tmp_path / "Backup"
    _make_backup(root, "udid-1", "iPhone A", "iPhone14,2", days_ago=5)
    _make_backup(root, "udid-2", "iPhone A", "iPhone14,2", days_ago=40)

    found = backups.find_backups(base=root)

    assert backups.stale_backups(found, keep_latest_per_device=1, older_than_days=90) == []
    stale = backups.stale_backups(found, keep_latest_per_device=1, older_than_days=10)
    assert len(stale) == 1
    assert stale[0].udid == "udid-2"


def test_to_candidate_wraps_backup(tmp_path):
    root = tmp_path / "Backup"
    _make_backup(root, "udid-1", "iPhone A", "iPhone14,2", days_ago=5)
    found = backups.find_backups(base=root)

    candidate = backups.to_candidate(found[0])

    assert candidate.category == "Device Backups"
    assert candidate.is_dir is True
    assert candidate.size_bytes == found[0].size_bytes
