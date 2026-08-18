from datetime import datetime, timedelta, timezone
from pathlib import Path

from filecleaner import quarantine
from filecleaner.models import Candidate


def _make_candidate(path, size=1000, is_dir=False, rule_id="system_caches", category="Caches"):
    return Candidate(
        path=path,
        size_bytes=size,
        is_dir=is_dir,
        mtime=0.0,
        rule_id=rule_id,
        category=category,
        risk="low",
    )


def test_quarantine_moves_file_and_records_manifest(sandbox_config, sandbox_home):
    target = sandbox_home / "Library" / "Caches" / "App" / "data.bin"
    target.parent.mkdir(parents=True)
    target.write_bytes(b"hello world")

    entries = quarantine.quarantine_candidates([_make_candidate(target, size=11)], sandbox_config)

    assert len(entries) == 1
    assert not target.exists()
    assert Path(entries[0].quarantine_path).exists()

    listed = quarantine.list_entries(sandbox_config)
    assert len(listed) == 1
    assert listed[0].original_path == str(target)


def test_quarantine_refuses_protected_path(sandbox_config, sandbox_home):
    target = sandbox_home / "Library" / "Caches" / "Important" / "data.bin"
    target.parent.mkdir(parents=True)
    target.write_bytes(b"hello world")
    sandbox_config["protected_paths"] = [str(target.parent)]

    entries = quarantine.quarantine_candidates([_make_candidate(target, size=11)], sandbox_config)

    assert entries == []
    assert target.exists()


def test_restore_round_trip(sandbox_config, sandbox_home):
    target = sandbox_home / "Library" / "Caches" / "App" / "data.bin"
    target.parent.mkdir(parents=True)
    target.write_bytes(b"hello world")

    entries = quarantine.quarantine_candidates([_make_candidate(target, size=11)], sandbox_config)
    assert not target.exists()

    restored = quarantine.restore_entries([entries[0].id], sandbox_config)

    assert len(restored) == 1
    assert target.exists()
    assert target.read_bytes() == b"hello world"

    remaining = quarantine.list_entries(sandbox_config)
    assert remaining == []


def test_purge_permanently_removes(sandbox_config, sandbox_home):
    target = sandbox_home / "Library" / "Caches" / "App" / "data.bin"
    target.parent.mkdir(parents=True)
    target.write_bytes(b"hello world")

    entries = quarantine.quarantine_candidates([_make_candidate(target, size=11)], sandbox_config)
    quarantine_path = entries[0].quarantine_path

    purged = quarantine.purge_entries([entries[0].id], sandbox_config)

    assert len(purged) == 1
    assert not Path(quarantine_path).exists()
    assert quarantine.list_entries(sandbox_config) == []


def test_secure_purge_overwrites_before_removing(sandbox_config, sandbox_home):
    target = sandbox_home / "Library" / "Caches" / "App" / "data.bin"
    target.parent.mkdir(parents=True)
    original = b"secret" * 1000
    target.write_bytes(original)

    entries = quarantine.quarantine_candidates([_make_candidate(target, size=len(original))], sandbox_config)
    quarantine_path = Path(entries[0].quarantine_path)

    # Overwrite directly so we can inspect the bytes before they're removed.
    quarantine._secure_overwrite_file(quarantine_path)
    assert quarantine_path.exists()
    assert quarantine_path.stat().st_size == len(original)
    assert quarantine_path.read_bytes() != original

    purged = quarantine.purge_entries([entries[0].id], sandbox_config, secure=True)
    assert len(purged) == 1
    assert not quarantine_path.exists()


def test_eligible_for_purge_respects_retention(sandbox_config, sandbox_home):
    target = sandbox_home / "Library" / "Caches" / "App" / "data.bin"
    target.parent.mkdir(parents=True)
    target.write_bytes(b"hello world")
    entries = quarantine.quarantine_candidates([_make_candidate(target, size=11)], sandbox_config)

    # Retention not yet elapsed.
    sandbox_config["retention_days"] = 30
    assert quarantine.eligible_for_purge(sandbox_config) == []

    # Backdate the manifest timestamp to simulate 40 days ago.
    import sqlite3

    from filecleaner import config as config_mod

    db_path = config_mod.get_manifest_db_path(sandbox_config)
    conn = sqlite3.connect(db_path)
    old_ts = (datetime.now(timezone.utc) - timedelta(days=40)).isoformat()
    conn.execute("UPDATE quarantine_entries SET timestamp = ? WHERE id = ?", (old_ts, entries[0].id))
    conn.commit()
    conn.close()

    eligible = quarantine.eligible_for_purge(sandbox_config)
    assert len(eligible) == 1
    assert eligible[0].id == entries[0].id
