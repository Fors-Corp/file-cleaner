"""Human-friendly formatting helpers (pure functions, no I/O)."""

from __future__ import annotations

import time
from datetime import UTC, datetime

_UNITS = ("B", "KB", "MB", "GB", "TB", "PB")


def human_size(num_bytes: float) -> str:
    """Render a byte count with a binary-scaled unit, e.g. ``1.5 GB``."""
    value = float(num_bytes)
    for unit in _UNITS:
        if abs(value) < 1024:
            return f"{int(value)} {unit}" if unit == "B" else f"{value:.1f} {unit}"
        value /= 1024
    return f"{value:.1f} EB"


def human_age(mtime: float, *, now: float | None = None) -> str:
    """Render how long ago ``mtime`` was, coarsely: ``today``, ``3 days``, ``2 months``..."""
    now = time.time() if now is None else now
    days = int(max(0.0, now - mtime) // 86400)
    if days == 0:
        return "today"
    if days == 1:
        return "1 day"
    if days < 60:
        return f"{days} days"
    months = days // 30
    if months < 24:
        return f"{months} months"
    years = days // 365
    return f"{years} years"


def iso_now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


def short_timestamp(iso: str) -> str:
    """Trim an ISO-8601 timestamp to ``YYYY-MM-DD HH:MM`` for tables."""
    return iso[:16].replace("T", " ")
