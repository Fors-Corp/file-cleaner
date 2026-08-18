"""Local, plain-text configuration.

Everything filecleaner does is local-only: no network calls, no telemetry,
nothing phones home. Config, quarantine manifest, and audit log all live
under the user's home directory with restrictive permissions (0700 dirs /
0600 files) since paths and filenames can reveal personal information.
"""

from __future__ import annotations

import os
import stat
import tomllib
from pathlib import Path
from typing import Any

import tomli_w

CONFIG_DIR = Path.home() / ".config" / "filecleaner"
CONFIG_FILE = CONFIG_DIR / "config.toml"

DATA_DIR = Path.home() / ".filecleaner"
DEFAULT_QUARANTINE_DIR = DATA_DIR / "quarantine"
AUDIT_LOG_PATH = DATA_DIR / "audit.log"

_DIR_MODE = 0o700
_FILE_MODE = 0o600


def default_config() -> dict[str, Any]:
    return {
        "retention_days": 30,
        "quarantine_dir": str(DEFAULT_QUARANTINE_DIR),
        "protected_paths": [],
        "scan_roots": [],  # empty = home dir + auto-detected external volumes
        "rule_overrides": {},  # rule_id -> bool, overrides a rule's enabled_by_default
        "hash_duplicates_max_bytes": 2_000_000_000,
    }


def _secure_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(path, _DIR_MODE)
    except OSError:
        pass


def _secure_file(path: Path) -> None:
    try:
        os.chmod(path, _FILE_MODE)
    except OSError:
        pass


def ensure_dirs() -> None:
    _secure_dir(CONFIG_DIR)
    _secure_dir(DATA_DIR)


def load_config() -> dict[str, Any]:
    ensure_dirs()
    defaults = default_config()
    if not CONFIG_FILE.exists():
        save_config(defaults)
        return defaults

    with CONFIG_FILE.open("rb") as f:
        loaded = tomllib.load(f)

    merged = {**defaults, **loaded}
    return merged


def save_config(config: dict[str, Any]) -> None:
    ensure_dirs()
    with CONFIG_FILE.open("wb") as f:
        tomli_w.dump(config, f)
    _secure_file(CONFIG_FILE)


def get_quarantine_dir(config: dict[str, Any]) -> Path:
    path = Path(config.get("quarantine_dir") or DEFAULT_QUARANTINE_DIR).expanduser()
    _secure_dir(path)
    return path


def get_manifest_db_path(config: dict[str, Any]) -> Path:
    return get_quarantine_dir(config) / "manifest.db"


def get_audit_log_path() -> Path:
    ensure_dirs()
    if not AUDIT_LOG_PATH.exists():
        AUDIT_LOG_PATH.touch()
    _secure_file(AUDIT_LOG_PATH)
    return AUDIT_LOG_PATH


def is_rule_enabled(config: dict[str, Any], rule_id: str, default: bool) -> bool:
    overrides = config.get("rule_overrides", {})
    return bool(overrides.get(rule_id, default))


def extra_protected_paths(config: dict[str, Any]) -> tuple[Path, ...]:
    return tuple(Path(p).expanduser() for p in config.get("protected_paths", []))


def add_keep_path(config: dict[str, Any], path: str) -> None:
    """Persistently exclude a path from all future scans/cleans (a user
    'always keep this' list, layered on top of — never replacing — the
    hardcoded safety deny-list)."""
    paths = config.setdefault("protected_paths", [])
    normalized = str(Path(path).expanduser())
    if normalized not in paths:
        paths.append(normalized)


def remove_keep_path(config: dict[str, Any], path: str) -> bool:
    paths = config.get("protected_paths", [])
    normalized = str(Path(path).expanduser())
    if normalized in paths:
        paths.remove(normalized)
        return True
    return False
