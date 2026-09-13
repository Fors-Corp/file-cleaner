"""Append-only local audit trail of every action File Cleaner takes.

Never written anywhere but the user's own machine, and never includes file
contents — only metadata (paths, sizes, rule ids, timestamps). One JSON
object per line; the file is rotated once (``audit.log.1``) when it grows
past ``MAX_LOG_BYTES`` so it cannot fill the disk it is supposed to free.
"""

from __future__ import annotations

import json
import os
from datetime import UTC, datetime
from typing import Any

from filecleaner.config import get_audit_log_path
from filecleaner.models import ScanResult

MAX_LOG_BYTES = 10 * 1024 * 1024


def _rotate_if_needed() -> None:
    path = get_audit_log_path()
    try:
        if path.stat().st_size < MAX_LOG_BYTES:
            return
        rotated = path.with_name(path.name + ".1")
        os.replace(path, rotated)
        path.touch()
        os.chmod(path, 0o600)
    except OSError:
        pass


def log_action(action: str, details: dict[str, Any]) -> None:
    entry = {
        "timestamp": datetime.now(UTC).isoformat(),
        "action": action,
        **details,
    }
    _rotate_if_needed()
    path = get_audit_log_path()
    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(entry, default=str) + "\n")


def log_scan(result: ScanResult) -> None:
    """Record a scan action: aggregate count/size plus the same per-category
    breakdown ``ScanResult.to_dict()`` already computes, so scan history
    feeds the stats dashboard without any extra bookkeeping. Shared by the
    CLI and TUI so both front-ends log scans identically."""
    log_action(
        "scan",
        {
            "candidate_count": len(result.candidates),
            "total_size": result.total_size,
            "categories": result.to_dict()["categories"],
        },
    )


def read_audit_log(
    limit: int | None = None,
    *,
    action: str | None = None,
) -> list[dict[str, Any]]:
    """Most recent entries last. Malformed lines are skipped, never fatal."""
    path = get_audit_log_path()
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return []
    entries: list[dict[str, Any]] = []
    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            parsed = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(parsed, dict):
            continue
        if action and parsed.get("action") != action:
            continue
        entries.append(parsed)
    if limit:
        entries = entries[-limit:]
    return entries
