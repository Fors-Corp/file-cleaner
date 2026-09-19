from datetime import UTC, datetime, timedelta
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

    result = quarantine.quarantine_candidates([_make_candidate(target, size=11)], sandbox_config)

    assert len(result.entries) == 1
    assert result.skipped == []
    assert result.session_id == result.entries[0].session_id
    assert result.total_size == 11
    assert not target.exists()
    assert Path(result.entries[0].quarantine_path).exists()

    listed = quarantine.list_entries(sandbox_config)
    assert len(listed) == 1
    assert listed[0].original_path == str(target)


def test_quarantine_refuses_protected_path(sandbox_config, sandbox_home):
    target = sandbox_home / "Library" / "Caches" / "Important" / "data.bin"
    target.parent.mkdir(parents=True)
    target.write_bytes(b"hello world")
    sandbox_config["protected_paths"] = [str(target.parent)]

    result = quarantine.quarantine_candidates([_make_candidate(target, size=11)], sandbox_config)

    assert result.entries == []
    assert len(result.skipped) == 1
    assert result.skipped[0].reason == "protected path"
    assert target.exists()


def test_quarantine_refuses_case_variant_of_protected_path(sandbox_config, sandbox_home):
    """A hand-edited plan can spell a protected directory in a different
    case; on a case-insensitive volume that spelling opens the real thing,
    so the pre-move gate has to see through it."""
    key = sandbox_home / ".ssh" / "id_rsa"
    key.parent.mkdir()
    key.write_bytes(b"secret")
    spelled = sandbox_home / ".SSH" / "id_rsa"

    result = quarantine.quarantine_candidates([_make_candidate(spelled, size=6)], sandbox_config)

    assert result.entries == []
    assert [s.reason for s in result.skipped] == ["protected path"]
    assert key.read_bytes() == b"secret"


def test_quarantine_refuses_own_data_dir(sandbox_config, sandbox_home):
    """The tool's own config/data/quarantine directories must never be
    quarantinable — that would eat the safety net itself."""
    quarantine_dir = Path(sandbox_config["quarantine_dir"])
    quarantine_dir.mkdir(parents=True, exist_ok=True)
    decoy = quarantine_dir / "some-old-session" / "leftover.bin"
    decoy.parent.mkdir(parents=True)
    decoy.write_bytes(b"not really a manifest")

    result = quarantine.quarantine_candidates([_make_candidate(decoy, size=100, category="Caches")], sandbox_config)

    assert result.entries == []
    assert result.skipped and result.skipped[0].reason == "protected path"
    assert decoy.exists()


def test_quarantine_skips_missing_file(sandbox_config, sandbox_home):
    missing = sandbox_home / "Library" / "Caches" / "Gone" / "data.bin"
    result = quarantine.quarantine_candidates([_make_candidate(missing, size=11)], sandbox_config)
    assert result.entries == []
    assert result.skipped[0].reason == "no longer exists"


def test_quarantine_enforces_allowed_roots(sandbox_config, sandbox_home):
    inside = sandbox_home / "Library" / "Caches" / "App" / "data.bin"
    inside.parent.mkdir(parents=True)
    inside.write_bytes(b"x")
    outside = sandbox_home.parent / "elsewhere" / "data.bin"
    outside.parent.mkdir(parents=True)
    outside.write_bytes(b"y")

    result = quarantine.quarantine_candidates(
        [_make_candidate(inside, size=1), _make_candidate(outside, size=1)],
        sandbox_config,
        allowed_roots=(sandbox_home,),
    )

    assert len(result.entries) == 1
    assert result.entries[0].original_path == str(inside)
    assert len(result.skipped) == 1
    assert "outside" in result.skipped[0].reason
    assert outside.exists()  # never touched


def test_restore_round_trip(sandbox_config, sandbox_home):
    target = sandbox_home / "Library" / "Caches" / "App" / "data.bin"
    target.parent.mkdir(parents=True)
    target.write_bytes(b"hello world")

    quarantined = quarantine.quarantine_candidates([_make_candidate(target, size=11)], sandbox_config)
    assert not target.exists()

    restored = quarantine.restore_entries([quarantined.entries[0].id], sandbox_config)

    assert len(restored.entries) == 1
    assert restored.skipped == []
    assert target.exists()
    assert target.read_bytes() == b"hello world"

    remaining = quarantine.list_entries(sandbox_config)
    assert remaining == []


def test_restore_avoids_overwriting_existing_file(sandbox_config, sandbox_home):
    target = sandbox_home / "Library" / "Caches" / "App" / "data.bin"
    target.parent.mkdir(parents=True)
    target.write_bytes(b"original")

    quarantined = quarantine.quarantine_candidates([_make_candidate(target, size=8)], sandbox_config)
    # Something new now occupies the original spot.
    target.write_bytes(b"replacement")

    restored = quarantine.restore_entries([quarantined.entries[0].id], sandbox_config)

    assert len(restored.entries) == 1
    assert target.read_bytes() == b"replacement"
    sibling = target.with_name(target.name + f".restored-{quarantined.entries[0].id}")
    assert sibling.read_bytes() == b"original"


def test_restore_skips_already_restored(sandbox_config, sandbox_home):
    target = sandbox_home / "Library" / "Caches" / "App" / "data.bin"
    target.parent.mkdir(parents=True)
    target.write_bytes(b"hello world")
    quarantined = quarantine.quarantine_candidates([_make_candidate(target, size=11)], sandbox_config)
    entry_id = quarantined.entries[0].id

    first = quarantine.restore_entries([entry_id], sandbox_config)
    second = quarantine.restore_entries([entry_id], sandbox_config)

    assert len(first.entries) == 1
    assert second.entries == []
    assert second.skipped[0].reason == "already restored or purged"


def test_restore_unknown_id_is_reported(sandbox_config, sandbox_home):
    result = quarantine.restore_entries([999999], sandbox_config)
    assert result.entries == []
    assert result.skipped[0].reason == "no such quarantine entry"


def test_purge_permanently_removes(sandbox_config, sandbox_home):
    target = sandbox_home / "Library" / "Caches" / "App" / "data.bin"
    target.parent.mkdir(parents=True)
    target.write_bytes(b"hello world")

    quarantined = quarantine.quarantine_candidates([_make_candidate(target, size=11)], sandbox_config)
    quarantine_path = quarantined.entries[0].quarantine_path

    purged = quarantine.purge_entries([quarantined.entries[0].id], sandbox_config)

    assert len(purged.entries) == 1
    assert not Path(quarantine_path).exists()
    assert quarantine.list_entries(sandbox_config) == []


def test_purge_skips_already_purged(sandbox_config, sandbox_home):
    target = sandbox_home / "Library" / "Caches" / "App" / "data.bin"
    target.parent.mkdir(parents=True)
    target.write_bytes(b"hello world")
    quarantined = quarantine.quarantine_candidates([_make_candidate(target, size=11)], sandbox_config)
    entry_id = quarantined.entries[0].id

    first = quarantine.purge_entries([entry_id], sandbox_config)
    second = quarantine.purge_entries([entry_id], sandbox_config)

    assert len(first.entries) == 1
    assert second.entries == []
    assert second.skipped[0].reason == "already purged"


def test_secure_purge_overwrites_before_removing(sandbox_config, sandbox_home):
    target = sandbox_home / "Library" / "Caches" / "App" / "data.bin"
    target.parent.mkdir(parents=True)
    original = b"secret" * 1000
    target.write_bytes(original)

    quarantined = quarantine.quarantine_candidates([_make_candidate(target, size=len(original))], sandbox_config)
    quarantine_path = Path(quarantined.entries[0].quarantine_path)

    # Overwrite directly so we can inspect the bytes before they're removed.
    quarantine._secure_overwrite_file(quarantine_path)
    assert quarantine_path.exists()
    assert quarantine_path.stat().st_size == len(original)
    assert quarantine_path.read_bytes() != original

    purged = quarantine.purge_entries([quarantined.entries[0].id], sandbox_config, secure=True)
    assert len(purged.entries) == 1
    assert not quarantine_path.exists()


def test_eligible_for_purge_respects_retention(sandbox_config, sandbox_home):
    target = sandbox_home / "Library" / "Caches" / "App" / "data.bin"
    target.parent.mkdir(parents=True)
    target.write_bytes(b"hello world")
    quarantined = quarantine.quarantine_candidates([_make_candidate(target, size=11)], sandbox_config)

    # Retention not yet elapsed.
    sandbox_config["retention_days"] = 30
    assert quarantine.eligible_for_purge(sandbox_config) == []

    # Backdate the manifest timestamp to simulate 40 days ago.
    import sqlite3

    from filecleaner import config as config_mod

    db_path = config_mod.get_manifest_db_path(sandbox_config)
    conn = sqlite3.connect(db_path)
    old_ts = (datetime.now(UTC) - timedelta(days=40)).isoformat()
    conn.execute("UPDATE quarantine_entries SET timestamp = ? WHERE id = ?", (old_ts, quarantined.entries[0].id))
    conn.commit()
    conn.close()

    eligible = quarantine.eligible_for_purge(sandbox_config)
    assert len(eligible) == 1
    assert eligible[0].id == quarantined.entries[0].id


def test_list_entries_filters_by_path_and_ids(sandbox_config, sandbox_home):
    a = sandbox_home / "Library" / "Caches" / "AppA" / "data.bin"
    b = sandbox_home / "Library" / "Caches" / "AppB" / "data.bin"
    for p in (a, b):
        p.parent.mkdir(parents=True)
        p.write_bytes(b"x")
    result = quarantine.quarantine_candidates(
        [_make_candidate(a, size=1), _make_candidate(b, size=1)], sandbox_config
    )
    ids = [e.id for e in result.entries]

    by_path = quarantine.list_entries(sandbox_config, path_contains="AppA")
    assert len(by_path) == 1 and "AppA" in by_path[0].original_path

    by_ids = quarantine.list_entries(sandbox_config, ids=(ids[0],))
    assert len(by_ids) == 1 and by_ids[0].id == ids[0]

    assert quarantine.list_entries(sandbox_config, ids=()) == []


def test_list_sessions_groups_by_session(sandbox_config, sandbox_home):
    a = sandbox_home / "Library" / "Caches" / "AppA" / "data.bin"
    a.parent.mkdir(parents=True)
    a.write_bytes(b"x" * 10)
    quarantine.quarantine_candidates([_make_candidate(a, size=10)], sandbox_config, session_id="session-one")

    b = sandbox_home / "Library" / "Caches" / "AppB" / "data.bin"
    b.parent.mkdir(parents=True)
    b.write_bytes(b"y" * 20)
    quarantine.quarantine_candidates([_make_candidate(b, size=20)], sandbox_config, session_id="session-two")

    sessions = quarantine.list_sessions(sandbox_config)
    by_id = {s.session_id: s for s in sessions}
    assert by_id["session-one"].count == 1
    assert by_id["session-one"].size_bytes == 10
    assert by_id["session-two"].size_bytes == 20


def test_overall_summary(sandbox_config, sandbox_home):
    assert quarantine.overall_summary(sandbox_config) == (0, 0)
    target = sandbox_home / "Library" / "Caches" / "App" / "data.bin"
    target.parent.mkdir(parents=True)
    target.write_bytes(b"x" * 42)
    quarantine.quarantine_candidates([_make_candidate(target, size=42)], sandbox_config)
    assert quarantine.overall_summary(sandbox_config) == (1, 42)


def test_history_by_category_groups_and_sums(sandbox_config, sandbox_home):
    a = sandbox_home / "Library" / "Caches" / "AppA" / "data.bin"
    a.parent.mkdir(parents=True)
    a.write_bytes(b"x" * 10)
    quarantine.quarantine_candidates([_make_candidate(a, size=10, category="Caches")], sandbox_config)

    b = sandbox_home / "Logs" / "old.log"
    b.parent.mkdir(parents=True)
    b.write_bytes(b"y" * 5)
    quarantine.quarantine_candidates([_make_candidate(b, size=5, category="Logs")], sandbox_config)

    history = {row["category"]: row for row in quarantine.history_by_category(sandbox_config)}
    assert history["Caches"]["size_bytes"] == 10
    assert history["Caches"]["count"] == 1
    assert history["Logs"]["size_bytes"] == 5


def test_history_by_category_includes_purged_entries(sandbox_config, sandbox_home):
    """Unlike overall_summary, history is the full record — purging an item
    must not erase it from the history view."""
    target = sandbox_home / "Library" / "Caches" / "App" / "data.bin"
    target.parent.mkdir(parents=True)
    target.write_bytes(b"x" * 42)
    result = quarantine.quarantine_candidates([_make_candidate(target, size=42)], sandbox_config)
    quarantine.purge_entries([e.id for e in result.entries], sandbox_config)

    assert quarantine.overall_summary(sandbox_config) == (0, 0)
    history = quarantine.history_by_category(sandbox_config)
    assert history == [{"category": "Caches", "count": 1, "size_bytes": 42}]


def test_history_by_day_buckets_by_date(sandbox_config, sandbox_home):
    target = sandbox_home / "Library" / "Caches" / "App" / "data.bin"
    target.parent.mkdir(parents=True)
    target.write_bytes(b"x" * 42)
    quarantine.quarantine_candidates([_make_candidate(target, size=42)], sandbox_config)

    today = datetime.now(UTC).strftime("%Y-%m-%d")
    history = quarantine.history_by_day(sandbox_config, days=30)
    assert history == [{"date": today, "size_bytes": 42, "count": 1}]


def test_history_by_day_excludes_entries_outside_window(sandbox_config, sandbox_home):
    import sqlite3

    from filecleaner import config as config_mod

    target = sandbox_home / "Library" / "Caches" / "App" / "data.bin"
    target.parent.mkdir(parents=True)
    target.write_bytes(b"x" * 42)
    quarantined = quarantine.quarantine_candidates([_make_candidate(target, size=42)], sandbox_config)

    db_path = config_mod.get_manifest_db_path(sandbox_config)
    conn = sqlite3.connect(db_path)
    old_ts = (datetime.now(UTC) - timedelta(days=40)).isoformat()
    conn.execute("UPDATE quarantine_entries SET timestamp = ? WHERE id = ?", (old_ts, quarantined.entries[0].id))
    conn.commit()
    conn.close()

    assert quarantine.history_by_day(sandbox_config, days=30) == []
