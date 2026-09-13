"""Named, saved snapshots of a subset of config keys ("scan profiles").

A profile lets you save a named combination of scan roots, rule
enable/disable overrides, per-rule threshold overrides, retention, and hash
limits — then switch between them (e.g. "quick", "deep",
"external-drives-only") without hand-editing config.toml each time.

Profiles are layered *on top of* the base config, never a replacement for
it: applying one only ever touches the keys it stores (``PROFILE_KEYS``),
so anything not tracked by profiles (e.g. ``quarantine_dir``,
``protected_paths``) always comes from the base config regardless of which
profile is active.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from filecleaner import config as config_mod

PROFILE_KEYS: tuple[str, ...] = (
    "scan_roots",
    "rule_overrides",
    "rule_param_overrides",
    "retention_days",
    "hash_duplicates_max_bytes",
)

_NAME_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")


class ProfileError(Exception):
    """An invalid profile name, or an operation on a profile that doesn't exist."""


def _profiles_dir() -> Path:
    d = config_mod.CONFIG_DIR / "profiles"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _validate_name(name: str) -> None:
    if not _NAME_RE.match(name):
        raise ProfileError(f"invalid profile name {name!r}: use 1-64 letters/digits/underscores/hyphens only")


def _profile_path(name: str) -> Path:
    _validate_name(name)
    return _profiles_dir() / f"{name}.toml"


def list_profiles() -> list[str]:
    return sorted(p.stem for p in _profiles_dir().glob("*.toml"))


def save_profile(name: str, config: dict[str, Any]) -> None:
    """Save the subset of ``config`` that profiles track under ``name``,
    overwriting any existing profile of that name."""
    path = _profile_path(name)
    snapshot = {key: config[key] for key in PROFILE_KEYS if key in config}
    config_mod.write_toml_atomic(path, snapshot)


def load_profile(name: str) -> dict[str, Any]:
    path = _profile_path(name)
    if not path.exists():
        raise ProfileError(f"no such profile: {name!r}")
    return config_mod.read_toml(path)


def delete_profile(name: str) -> bool:
    path = _profile_path(name)
    if not path.exists():
        return False
    path.unlink()
    return True


def apply_profile(config: dict[str, Any], name: str) -> dict[str, Any]:
    """Return a new config dict with ``name``'s saved keys layered on top of
    ``config``. Does not mutate ``config`` or write anything to disk —
    callers decide whether/how to persist the result."""
    profile = load_profile(name)
    merged = dict(config)
    merged.update(profile)
    config_mod.validate_config(merged)
    return merged
