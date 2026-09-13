import subprocess
import sys

import pytest

from filecleaner import schedule as schedule_mod


@pytest.fixture(autouse=True)
def _mock_launchctl(monkeypatch):
    """Never actually invoke launchctl in tests — record calls instead."""
    calls: list[list[str]] = []

    def fake_launchctl(*args):
        calls.append(list(args))
        return subprocess.CompletedProcess(args=["launchctl", *args], returncode=0, stdout="", stderr="")

    monkeypatch.setattr(schedule_mod, "_launchctl", fake_launchctl)
    return calls


def test_enable_writes_plist_and_bootstraps(sandbox_home, _mock_launchctl):
    path = schedule_mod.enable(every_hours=6)
    assert path.exists()
    assert path == schedule_mod.plist_path()
    assert path.parent == schedule_mod.LAUNCH_AGENTS_DIR

    import plistlib

    data = plistlib.loads(path.read_bytes())
    assert data["Label"] == schedule_mod.LABEL
    assert data["StartInterval"] == 6 * 3600
    assert data["ProgramArguments"] == [sys.executable, "-m", "filecleaner", "scan", "--json"]

    kinds = [c[0] for c in _mock_launchctl]
    assert "bootstrap" in kinds


def test_enable_rejects_non_positive_interval(sandbox_home):
    with pytest.raises(schedule_mod.ScheduleError):
        schedule_mod.enable(every_hours=0)


def test_disable_removes_plist(sandbox_home, _mock_launchctl):
    schedule_mod.enable(every_hours=6)
    assert schedule_mod.disable() is True
    assert not schedule_mod.plist_path().exists()
    assert schedule_mod.disable() is False


def test_status_reports_not_installed(sandbox_home):
    info = schedule_mod.status()
    assert info == {"installed": False, "loaded": False, "plist_path": str(schedule_mod.plist_path())}


def test_status_reports_installed(sandbox_home, _mock_launchctl):
    schedule_mod.enable(every_hours=12)
    info = schedule_mod.status()
    assert info["installed"] is True
    assert info["loaded"] is True  # mocked launchctl always returns success


def test_enable_bootout_before_bootstrap_when_already_installed(sandbox_home, _mock_launchctl):
    schedule_mod.enable(every_hours=6)
    schedule_mod.enable(every_hours=12)  # re-enabling should bootout the old one first
    kinds = [c[0] for c in _mock_launchctl]
    assert kinds.count("bootout") >= 1
    assert kinds.count("bootstrap") == 2
