"""JSON serialisation for ``--json`` output (scripting and assistive tooling)."""

from __future__ import annotations

import dataclasses
import json
import sys
from datetime import date, datetime
from pathlib import Path
from typing import Any, TextIO


def to_jsonable(value: Any) -> Any:
    """Recursively convert dataclasses, Paths and datetimes into JSON-safe values."""
    if hasattr(value, "to_dict") and callable(value.to_dict):
        return to_jsonable(value.to_dict())
    if dataclasses.is_dataclass(value) and not isinstance(value, type):
        return {f.name: to_jsonable(getattr(value, f.name)) for f in dataclasses.fields(value)}
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, (datetime, date)):
        return value.isoformat()
    if isinstance(value, dict):
        return {str(k): to_jsonable(v) for k, v in value.items()}
    if isinstance(value, (list, tuple, set, frozenset)):
        return [to_jsonable(v) for v in value]
    return value


def dumps(value: Any) -> str:
    return json.dumps(to_jsonable(value), indent=2, ensure_ascii=False)


def emit(value: Any, stream: TextIO | None = None) -> None:
    (stream or sys.stdout).write(dumps(value) + "\n")
