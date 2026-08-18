"""Walks scan roots and turns rule matches into sized Candidate objects.

Only path metadata (name, size, mtime) is ever read here — file contents
are never opened. Every match is checked against the hardcoded safety
deny-list before it's even reported as a candidate, not just before a
destructive action.
"""

from __future__ import annotations

import time
from pathlib import Path
from typing import Any

from filecleaner import config as config_mod
from filecleaner import safety
from filecleaner.models import Candidate, Rule, ScanResult
from filecleaner.rules import BUILTIN_RULES
from filecleaner.volumes import list_volumes


def _is_excluded(path: Path, base: Path, exclude_globs: tuple[str, ...]) -> bool:
    try:
        rel_str = str(path.relative_to(base))
    except ValueError:
        return False
    for pattern in exclude_globs:
        prefix = pattern.rstrip("*").rstrip("/")
        if prefix and (rel_str == prefix or rel_str.startswith(prefix + "/")):
            return True
    return False


def _dir_size(path: Path) -> int:
    total = 0
    try:
        for entry in path.rglob("*"):
            try:
                if entry.is_symlink():
                    continue
                if entry.is_file():
                    total += entry.stat().st_size
            except OSError:
                continue
    except OSError:
        pass
    return total


def _scan_scope(
    base: Path,
    rule: Rule,
    result: ScanResult,
    extra_protected: tuple[Path, ...],
) -> None:
    if not base.is_dir():
        return
    now = time.time()
    for pattern in rule.include_globs:
        try:
            matches = list(base.glob(pattern))
        except OSError as exc:
            result.errors.append(f"{rule.id}: {exc}")
            continue

        for match in matches:
            if match.is_symlink():
                continue
            if _is_excluded(match, base, rule.exclude_globs):
                continue
            if safety.is_protected(match, extra_protected=extra_protected):
                continue
            try:
                st = match.lstat()
            except OSError:
                continue

            age_days = (now - st.st_mtime) / 86400
            if age_days < rule.min_age_days:
                continue

            is_dir = match.is_dir()
            size = _dir_size(match) if is_dir else st.st_size
            if size < rule.min_size_bytes:
                continue

            result.candidates.append(
                Candidate(
                    path=match,
                    size_bytes=size,
                    is_dir=is_dir,
                    mtime=st.st_mtime,
                    rule_id=rule.id,
                    category=rule.category,
                    risk=rule.risk,
                )
            )


def run_scan(
    config: dict[str, Any],
    *,
    only_rules: set[str] | None = None,
    include_disabled: bool = False,
    extra_excludes: tuple[Path, ...] = (),
) -> ScanResult:
    home = Path.home()
    result = ScanResult(scan_roots=[home])
    extra_protected = config_mod.extra_protected_paths(config) + tuple(extra_excludes)
    volumes = None

    for rule in BUILTIN_RULES:
        if only_rules is not None:
            if rule.id not in only_rules:
                continue
        else:
            enabled = config_mod.is_rule_enabled(config, rule.id, rule.enabled_by_default)
            if not enabled and not include_disabled:
                continue

        if rule.scope == "home":
            _scan_scope(home, rule, result, extra_protected)
        elif rule.scope == "each_volume":
            if volumes is None:
                volumes = list_volumes()
            for vol in volumes:
                if vol.is_root:
                    continue
                _scan_scope(vol.path, rule, result, extra_protected)
                if vol.path not in result.scan_roots:
                    result.scan_roots.append(vol.path)

    return result
