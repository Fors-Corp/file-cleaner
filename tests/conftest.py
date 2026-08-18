from __future__ import annotations

import os
import time
from pathlib import Path

import pytest

from filecleaner import config as config_mod


@pytest.fixture
def sandbox_home(tmp_path, monkeypatch):
    """Redirect Path.home() and all filecleaner config/data paths into a
    throwaway tmp_path sandbox so tests never touch the real filesystem."""
    fake_home = tmp_path / "home"
    fake_home.mkdir()
    fake_config_dir = tmp_path / "config"
    fake_data_dir = tmp_path / "data"

    monkeypatch.setattr(Path, "home", lambda: fake_home)
    monkeypatch.setattr(config_mod, "CONFIG_DIR", fake_config_dir)
    monkeypatch.setattr(config_mod, "CONFIG_FILE", fake_config_dir / "config.toml")
    monkeypatch.setattr(config_mod, "DATA_DIR", fake_data_dir)
    monkeypatch.setattr(config_mod, "DEFAULT_QUARANTINE_DIR", fake_data_dir / "quarantine")
    monkeypatch.setattr(config_mod, "AUDIT_LOG_PATH", fake_data_dir / "audit.log")

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
