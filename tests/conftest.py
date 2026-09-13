from __future__ import annotations

import os
import time
from pathlib import Path

import pytest

from filecleaner import config as config_mod
from filecleaner import safety as safety_mod
from filecleaner import schedule as schedule_mod


@pytest.fixture(autouse=True)
def _reset_safety_cache():
    """`safety._volume_roots()` caches mounted volumes briefly for
    performance; start every test with a clean slate so tests can never
    observe another test's cached mount state."""
    safety_mod.reset_caches()
    yield
    safety_mod.reset_caches()


@pytest.fixture
def sandbox_home(tmp_path, monkeypatch):
    """Redirect Path.home() and all filecleaner config/data paths into a
    throwaway tmp_path sandbox so tests never touch the real filesystem."""
    fake_home = tmp_path / "home"
    fake_home.mkdir()
    fake_config_dir = tmp_path / "config"
    fake_data_dir = tmp_path / "data"

    monkeypatch.setattr(Path, "home", lambda: fake_home)
    # Path.expanduser() reads the HOME environment variable directly (not
    # Path.home()), so both must point at the sandbox for "~" to resolve
    # inside it consistently.
    monkeypatch.setenv("HOME", str(fake_home))
    monkeypatch.setattr(config_mod, "CONFIG_DIR", fake_config_dir)
    monkeypatch.setattr(config_mod, "CONFIG_FILE", fake_config_dir / "config.toml")
    monkeypatch.setattr(config_mod, "DATA_DIR", fake_data_dir)
    monkeypatch.setattr(config_mod, "DEFAULT_QUARANTINE_DIR", fake_data_dir / "quarantine")
    monkeypatch.setattr(config_mod, "AUDIT_LOG_PATH", fake_data_dir / "audit.log")
    # Never let a test write a real LaunchAgent, even if it forgets to mock launchctl.
    monkeypatch.setattr(schedule_mod, "LAUNCH_AGENTS_DIR", tmp_path / "LaunchAgents")
    # scanner.run_scan()/count_total_dirs() default their scan root to the
    # current working directory, not Path.home() — chdir into the fake home
    # so "scan with no explicit root" in tests means the same "whole-machine"
    # scan it always has, exactly as it would for a real user running
    # `fclean scan` from their own home directory.
    monkeypatch.chdir(fake_home)

    return fake_home


@pytest.fixture
def sandbox_config(tmp_path, sandbox_home):
    cfg = config_mod.default_config()
    cfg["quarantine_dir"] = str(tmp_path / "quarantine")
    return cfg


def _age_path(path: Path, days: float) -> None:
    """Backdate a file/dir's mtime so age-based rules treat it as old."""
    old = time.time() - days * 86400
    os.utime(path, (old, old))


@pytest.fixture
def age_path():
    return _age_path
