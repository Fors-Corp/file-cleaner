"""Append-only local audit trail of every action filecleaner takes.

Never written anywhere but the user's own machine, and never includes file
contents — only metadata (paths, sizes, rule ids, timestamps).
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

from filecleaner.config import get_audit_log_path


def log_action(action: str, details: dict[str, Any]) -> None:
    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "action": action,
        **details,
    }
    path = get_audit_log_path()
    with path.open("a") as f:
        f.write(json.dumps(entry, default=str) + "\n")


def read_audit_log(limit: int | None = None) -> list[dict[str, Any]]:
    path = get_audit_log_path()
    lines = path.read_text().splitlines()
    if limit:
        lines = lines[-limit:]
    return [json.loads(line) for line in lines if line.strip()]
