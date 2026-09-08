import time
from pathlib import Path

import pytest

from filecleaner import plan as plan_mod
from filecleaner.models import Candidate, ScanResult


def _candidate(path: Path, size: int, is_dir: bool = False) -> Candidate:
    st = path.stat()
    return Candidate(
        path=path,
        size_bytes=size,
        is_dir=is_dir,
        mtime=st.st_mtime,
        rule_id="system_caches",
        category="Caches",
        risk="low",
    )


def test_save_and_load_round_trip(tmp_path):
    f = tmp_path / "a.bin"
    f.write_bytes(b"x" * 100)
    result = ScanResult(scan_roots=[tmp_path], candidates=[_candidate(f, 100)])
    original = plan_mod.CleanupPlan.from_scan(result, note="test plan")

    plan_file = tmp_path / "plan.json"
    plan_mod.save_plan(original, plan_file)
    assert (plan_file.stat().st_mode & 0o777) == 0o600

    loaded = plan_mod.load_plan(plan_file)
    assert loaded.note == "test plan"
    assert loaded.total_size == 100
    assert len(loaded.candidates) == 1
    assert loaded.candidates[0].path == f


def test_load_plan_rejects_bad_json(tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text("{not json")
    with pytest.raises(plan_mod.PlanError):
        plan_mod.load_plan(bad)


def test_load_plan_rejects_missing_file(tmp_path):
    with pytest.raises(plan_mod.PlanError):
        plan_mod.load_plan(tmp_path / "does-not-exist.json")


def test_load_plan_rejects_wrong_format_version(tmp_path):
    import json

    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps({"format_version": 999, "candidates": []}))
    with pytest.raises(plan_mod.PlanError):
        plan_mod.load_plan(bad)


def test_revalidate_accepts_unchanged_candidate(tmp_path):
    f = tmp_path / "a.bin"
    f.write_bytes(b"x" * 50)
    result = ScanResult(scan_roots=[tmp_path], candidates=[_candidate(f, 50)])
    p = plan_mod.CleanupPlan.from_scan(result)

    fresh, stale = plan_mod.revalidate(p)
    assert len(fresh) == 1
    assert stale == []


def test_revalidate_flags_deleted_file(tmp_path):
    f = tmp_path / "a.bin"
    f.write_bytes(b"x" * 50)
    result = ScanResult(scan_roots=[tmp_path], candidates=[_candidate(f, 50)])
    p = plan_mod.CleanupPlan.from_scan(result)
    f.unlink()

    fresh, stale = plan_mod.revalidate(p)
    assert fresh == []
    assert stale[0].reason == "no longer exists"


def test_revalidate_flags_modified_file(tmp_path):
    f = tmp_path / "a.bin"
    f.write_bytes(b"x" * 50)
    result = ScanResult(scan_roots=[tmp_path], candidates=[_candidate(f, 50)])
    p = plan_mod.CleanupPlan.from_scan(result)

    time.sleep(0.01)
    f.write_bytes(b"y" * 999)  # size changed

    fresh, stale = plan_mod.revalidate(p)
    assert fresh == []
    assert "modified" in stale[0].reason


def test_revalidate_flags_file_that_became_a_directory(tmp_path):
    f = tmp_path / "a.bin"
    f.write_bytes(b"x" * 50)
    result = ScanResult(scan_roots=[tmp_path], candidates=[_candidate(f, 50)])
    p = plan_mod.CleanupPlan.from_scan(result)

    f.unlink()
    f.mkdir()

    fresh, stale = plan_mod.revalidate(p)
    assert fresh == []
    assert "file and directory" in stale[0].reason


def test_revalidate_flags_symlink_substitution(tmp_path):
    f = tmp_path / "a.bin"
    f.write_bytes(b"x" * 50)
    result = ScanResult(scan_roots=[tmp_path], candidates=[_candidate(f, 50)])
    p = plan_mod.CleanupPlan.from_scan(result)

    real = tmp_path / "real.bin"
    real.write_bytes(b"z" * 50)
    f.unlink()
    f.symlink_to(real)

    fresh, stale = plan_mod.revalidate(p)
    assert fresh == []
    assert "symlink" in stale[0].reason
