"""Local, plain-text configuration with validation.

Everything File Cleaner does is local-only: no network calls, no telemetry,
nothing phones home. Config, quarantine manifest, and audit log all live
under the user's home directory with restrictive permissions (0700 dirs /
0600 files) since paths and filenames can reveal personal information.

Locations (override with environment variables for testing or portability):

* ``FILECLEANER_CONFIG_DIR`` — default ``$XDG_CONFIG_HOME/filecleaner`` or
  ``~/.config/filecleaner``
* ``FILECLEANER_DATA_DIR`` — default ``~/.filecleaner``
"""

from __future__ import annotations

import contextlib
import os
import tempfile
import tomllib
from collections.abc import Callable
from pathlib import Path
from typing import Any

import tomli_w


class ConfigError(Exception):
    """The configuration file is unreadable or contains an invalid value."""


def _config_dir_from_env() -> Path:
    explicit = os.environ.get("FILECLEANER_CONFIG_DIR")
    if explicit:
        return Path(explicit).expanduser()
    xdg = os.environ.get("XDG_CONFIG_HOME")
    base = Path(xdg).expanduser() if xdg else Path.home() / ".config"
    return base / "filecleaner"


def _data_dir_from_env() -> Path:
    explicit = os.environ.get("FILECLEANER_DATA_DIR")
    if explicit:
        return Path(explicit).expanduser()
    return Path.home() / ".filecleaner"


CONFIG_DIR = _config_dir_from_env()
CONFIG_FILE = CONFIG_DIR / "config.toml"

DATA_DIR = _data_dir_from_env()
DEFAULT_QUARANTINE_DIR = DATA_DIR / "quarantine"
AUDIT_LOG_PATH = DATA_DIR / "audit.log"

# Name of the per-volume quarantine folder created at the root of an
# external volume when ``volume_local_quarantine`` is on.
VOLUME_QUARANTINE_DIRNAME = ".filecleaner-quarantine"

_DIR_MODE = 0o700
_FILE_MODE = 0o600


# --------------------------------------------------------------------------
# Schema
# --------------------------------------------------------------------------


def _check_non_negative_int(value: Any, key: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ConfigError(f"{key}: expected an integer, got {type(value).__name__}")
    if value < 0:
        raise ConfigError(f"{key}: must be >= 0, got {value}")
    return value


def _check_bool(value: Any, key: str) -> bool:
    if not isinstance(value, bool):
        raise ConfigError(f"{key}: expected true/false, got {type(value).__name__}")
    return value


def _check_str(value: Any, key: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ConfigError(f"{key}: expected a non-empty string")
    return value


def _check_str_list(value: Any, key: str) -> list[str]:
    if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
        raise ConfigError(f"{key}: expected a list of strings")
    return list(value)


def _check_overrides(value: Any, key: str) -> dict[str, bool]:
    if not isinstance(value, dict):
        raise ConfigError(f"{key}: expected a table of rule_id = true/false")
    for rule_id, flag in value.items():
        if not isinstance(flag, bool):
            raise ConfigError(f"{key}.{rule_id}: expected true/false, got {type(flag).__name__}")
    return dict(value)


def _check_rules(value: Any, key: str) -> list[dict[str, Any]]:
    if not isinstance(value, list) or not all(isinstance(v, dict) for v in value):
        raise ConfigError(f"{key}: expected an array of tables ([[rules]] blocks)")
    return list(value)


def _check_positive_int(value: Any, key: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ConfigError(f"{key}: expected an integer, got {type(value).__name__}")
    if value < 1:
        raise ConfigError(f"{key}: must be >= 1, got {value}")
    return value


def _check_optional_str(value: Any, key: str) -> str:
    if not isinstance(value, str):
        raise ConfigError(f"{key}: expected a string")
    return value


_PARAM_OVERRIDE_FIELDS = ("min_age_days", "min_size_bytes")


def _check_rule_param_overrides(value: Any, key: str) -> dict[str, dict[str, int]]:
    if not isinstance(value, dict):
        raise ConfigError(f"{key}: expected a table of rule_id = {{min_age_days=.., min_size_bytes=..}}")
    result: dict[str, dict[str, int]] = {}
    for rule_id, params in value.items():
        if not isinstance(params, dict):
            raise ConfigError(f"{key}.{rule_id}: expected a table")
        unknown = set(params) - set(_PARAM_OVERRIDE_FIELDS)
        if unknown:
            raise ConfigError(
                f"{key}.{rule_id}: unknown field(s) {sorted(unknown)}; allowed: {list(_PARAM_OVERRIDE_FIELDS)}"
            )
        cleaned: dict[str, int] = {}
        for field_name, raw in params.items():
            if isinstance(raw, bool) or not isinstance(raw, int) or raw < 0:
                raise ConfigError(f"{key}.{rule_id}.{field_name}: must be a non-negative integer")
            cleaned[field_name] = raw
        result[rule_id] = cleaned
    return result


# key -> (default, validator, one-line description shown by `config show`)
CONFIG_SCHEMA: dict[str, tuple[Any, Callable[[Any, str], Any], str]] = {
    "retention_days": (
        30,
        _check_non_negative_int,
        "Days an item must sit in quarantine before `quarantine purge` will touch it.",
    ),
    "quarantine_dir": (
        str(DEFAULT_QUARANTINE_DIR),
        _check_str,
        "Primary quarantine folder (used for anything on the same volume as it).",
    ),
    "volume_local_quarantine": (
        True,
        _check_bool,
        "Quarantine items from other volumes into a folder on that same volume "
        "(instant rename, no copy). Falls back to quarantine_dir when the volume is read-only.",
    ),
    "protected_paths": (
        [],
        _check_str_list,
        "Paths that are never touched, on top of the built-in deny-list (see `config keep`).",
    ),
    "scan_roots": (
        [],
        _check_str_list,
        "Roots to scan. Empty = home directory + every mounted external volume.",
    ),
    "rule_overrides": (
        {},
        _check_overrides,
        "rule_id = true/false to force a rule on or off regardless of its default.",
    ),
    "hash_duplicates_max_bytes": (
        2_000_000_000,
        _check_non_negative_int,
        "Files larger than this are never hashed (duplicate search / manifest integrity).",
    ),
    "rules": (
        [],
        _check_rules,
        "Custom rules ([[rules]] tables) — see README for the fields.",
    ),
    "rule_param_overrides": (
        {},
        _check_rule_param_overrides,
        "rule_id = {min_age_days=.., min_size_bytes=..} to override a builtin rule's thresholds "
        "without redefining it as a custom rule.",
    ),
    "scan_concurrency": (
        4,
        _check_positive_int,
        "Max number of (rule, root) walks to run in parallel during a scan. Scanning is I/O-bound, "
        "so this can exceed the CPU core count.",
    ),
    "active_profile": (
        "",
        _check_optional_str,
        "Name of the currently active scan profile (empty = none / base config only).",
    ),
}


def default_config() -> dict[str, Any]:
    cfg = {key: _copy(default) for key, (default, _validator, _desc) in CONFIG_SCHEMA.items()}
    # CONFIG_SCHEMA's "quarantine_dir" default was captured once at import
    # time; re-resolve it from the current DEFAULT_QUARANTINE_DIR so that
    # overriding it later (tests, or FILECLEANER_DATA_DIR at a fresh import)
    # is actually honoured instead of silently falling back to whatever
    # path was live the moment this module first loaded.
    cfg["quarantine_dir"] = str(DEFAULT_QUARANTINE_DIR)
    return cfg


def _copy(value: Any) -> Any:
    if isinstance(value, list):
        return list(value)
    if isinstance(value, dict):
        return dict(value)
    return value


def validate_config(config: dict[str, Any]) -> list[str]:
    """Validate in place. Returns non-fatal warnings; raises ``ConfigError`` on fatal problems."""
    warnings: list[str] = []
    for key, value in list(config.items()):
        if key not in CONFIG_SCHEMA:
            warnings.append(f"unknown config key {key!r} (ignored)")
            continue
        _default, validator, _desc = CONFIG_SCHEMA[key]
        config[key] = validator(value, key)
    return warnings


# --------------------------------------------------------------------------
# Filesystem plumbing
# --------------------------------------------------------------------------


def _secure_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)
    with contextlib.suppress(OSError):
        os.chmod(path, _DIR_MODE)


def _secure_file(path: Path) -> None:
    with contextlib.suppress(OSError):
        os.chmod(path, _FILE_MODE)


def ensure_dirs() -> None:
    _secure_dir(CONFIG_DIR)
    _secure_dir(DATA_DIR)


def load_config(*, warnings: list[str] | None = None) -> dict[str, Any]:
    """Load, validate and return the merged configuration.

    Creates a default config file on first run. Non-fatal problems are
    appended to ``warnings`` if a list is given.
    """
    ensure_dirs()
    defaults = default_config()
    if not CONFIG_FILE.exists():
        save_config(defaults)
        return defaults

    loaded = read_toml(CONFIG_FILE)
    merged = {**defaults, **loaded}
    found = validate_config(merged)
    if warnings is not None:
        warnings.extend(found)
    return merged


def read_toml(path: Path) -> dict[str, Any]:
    """Read one plain TOML file. Shared by config and profile loading so
    both get the same error handling."""
    try:
        with path.open("rb") as f:
            return tomllib.load(f)
    except tomllib.TOMLDecodeError as exc:
        raise ConfigError(f"{path} is not valid TOML: {exc}") from exc
    except OSError as exc:
        raise ConfigError(f"could not read {path}: {exc}") from exc


def write_toml_atomic(path: Path, data: dict[str, Any]) -> None:
    """Atomically write ``data`` as TOML (temp file + rename) with 0600
    permissions. Shared by config and profile saving."""
    fd, tmp_name = tempfile.mkstemp(prefix=".tmp-", suffix=".toml", dir=path.parent)
    tmp = Path(tmp_name)
    try:
        with os.fdopen(fd, "wb") as f:
            tomli_w.dump(data, f)
        _secure_file(tmp)
        os.replace(tmp, path)
    except BaseException:
        tmp.unlink(missing_ok=True)
        raise
    _secure_file(path)


def save_config(config: dict[str, Any]) -> None:
    """Atomically write the config (temp file + rename) with 0600 permissions."""
    ensure_dirs()
    validate_config(config)
    write_toml_atomic(CONFIG_FILE, config)


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


def data_paths_to_protect(config: dict[str, Any]) -> tuple[Path, ...]:
    """File Cleaner's own state must never be scanned, quarantined or purged
    as if it were junk — that would eat the safety net itself."""
    return (
        CONFIG_DIR,
        DATA_DIR,
        Path(config.get("quarantine_dir") or DEFAULT_QUARANTINE_DIR).expanduser(),
    )


# --------------------------------------------------------------------------
# Accessors
# --------------------------------------------------------------------------


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


def get_rule_param_override(config: dict[str, Any], rule_id: str) -> dict[str, int]:
    return dict(config.get("rule_param_overrides", {}).get(rule_id, {}))


def set_rule_param_override(
    config: dict[str, Any], rule_id: str, *, min_age_days: int | None = None, min_size_bytes: int | None = None
) -> dict[str, int]:
    """Set one or both threshold overrides for ``rule_id``, leaving any other
    already-set field on that rule untouched."""
    overrides = config.setdefault("rule_param_overrides", {})
    entry = dict(overrides.get(rule_id, {}))
    if min_age_days is not None:
        entry["min_age_days"] = min_age_days
    if min_size_bytes is not None:
        entry["min_size_bytes"] = min_size_bytes
    overrides[rule_id] = entry
    return entry


def clear_rule_param_override(config: dict[str, Any], rule_id: str) -> bool:
    overrides = config.get("rule_param_overrides", {})
    if rule_id in overrides:
        del overrides[rule_id]
        return True
    return False


def set_value(config: dict[str, Any], key: str, raw: str) -> Any:
    """Parse ``raw`` (typed from the command line) into the right type for
    ``key``, validate it, store it and return the parsed value."""
    if key not in CONFIG_SCHEMA:
        raise ConfigError(f"unknown config key {key!r}; valid keys: {', '.join(sorted(CONFIG_SCHEMA))}")
    if key in ("rule_overrides", "rules", "rule_param_overrides"):
        raise ConfigError(
            f"{key} cannot be set from the command line; use `config enable/disable`, "
            f"`config threshold`, or edit {CONFIG_FILE}"
        )
    default, validator, _desc = CONFIG_SCHEMA[key]
    text = raw.strip()
    value: Any
    if isinstance(default, bool):
        lowered = text.lower()
        if lowered in ("1", "true", "yes", "on"):
            value = True
        elif lowered in ("0", "false", "no", "off"):
            value = False
        else:
            raise ConfigError(f"{key}: expected true/false, got {raw!r}")
    elif isinstance(default, int):
        try:
            value = int(text.replace("_", ""))
        except ValueError as exc:
            raise ConfigError(f"{key}: expected an integer, got {raw!r}") from exc
    elif isinstance(default, list):
        value = [] if not text else [p.strip() for p in text.split(",") if p.strip()]
    else:
        value = text
    config[key] = validator(value, key)
    return config[key]
