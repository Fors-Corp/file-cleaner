"""Plain data types shared by every layer of File Cleaner.

Nothing in this module touches the filesystem. Keeping the models free of
I/O is what lets the CLI, the TUI, the JSON output mode and the test suite
all speak the same language.
"""

from __future__ import annotations

import os
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Literal

RuleKind = Literal["file", "dir"]
RuleScope = Literal["home", "each_volume"]
RuleRisk = Literal["low", "medium", "high"]

RULE_KINDS: tuple[str, ...] = ("file", "dir")
RULE_SCOPES: tuple[str, ...] = ("home", "each_volume")
RULE_RISKS: tuple[str, ...] = ("low", "medium", "high")


@dataclass(frozen=True)
class Rule:
    """A declarative description of one category of removable data.

    ``kind`` decides whether matches are treated as individual files or as
    whole directories (a directory match is quarantined as a unit and its
    contents are never listed separately). ``scope`` decides which roots
    the include globs are evaluated against.
    """

    id: str
    label: str
    category: str
    description: str
    enabled_by_default: bool
    risk: str
    kind: str
    scope: str
    include_globs: tuple[str, ...]
    exclude_globs: tuple[str, ...] = ()
    min_age_days: int = 0
    min_size_bytes: int = 0
    source: str = "builtin"  # "builtin" | "custom"

    def validate(self) -> None:
        """Raise ``ValueError`` describing the first problem found."""
        if not self.id or not self.id.replace("_", "").replace("-", "").isalnum():
            raise ValueError(f"rule id {self.id!r} must be alphanumeric (underscores/hyphens allowed)")
        if not self.label:
            raise ValueError(f"rule {self.id!r}: label is required")
        if not self.category:
            raise ValueError(f"rule {self.id!r}: category is required")
        if self.kind not in RULE_KINDS:
            raise ValueError(f"rule {self.id!r}: kind must be one of {RULE_KINDS}, got {self.kind!r}")
        if self.scope not in RULE_SCOPES:
            raise ValueError(f"rule {self.id!r}: scope must be one of {RULE_SCOPES}, got {self.scope!r}")
        if self.risk not in RULE_RISKS:
            raise ValueError(f"rule {self.id!r}: risk must be one of {RULE_RISKS}, got {self.risk!r}")
        if not self.include_globs:
            raise ValueError(f"rule {self.id!r}: at least one include glob is required")
        for glob in (*self.include_globs, *self.exclude_globs):
            if not glob or glob.startswith("/") or glob.startswith("~"):
                raise ValueError(
                    f"rule {self.id!r}: glob {glob!r} must be relative to the scan root (no leading '/' or '~')"
                )
            if ".." in Path(glob).parts:
                raise ValueError(f"rule {self.id!r}: glob {glob!r} must not contain '..'")
        if self.min_age_days < 0:
            raise ValueError(f"rule {self.id!r}: min_age_days must be >= 0")
        if self.min_size_bytes < 0:
            raise ValueError(f"rule {self.id!r}: min_size_bytes must be >= 0")

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["include_globs"] = list(self.include_globs)
        data["exclude_globs"] = list(self.exclude_globs)
        return data


@dataclass
class Candidate:
    """Something a rule matched and that could be moved to quarantine."""

    path: Path
    size_bytes: int
    is_dir: bool
    mtime: float
    rule_id: str
    category: str
    risk: str

    @property
    def age_days(self) -> float:
        return max(0.0, (time.time() - self.mtime) / 86400)

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": str(self.path),
            "size_bytes": self.size_bytes,
            "is_dir": self.is_dir,
            "mtime": self.mtime,
            "rule_id": self.rule_id,
            "category": self.category,
            "risk": self.risk,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Candidate:
        return cls(
            path=Path(str(data["path"])),
            size_bytes=int(data["size_bytes"]),
            is_dir=bool(data["is_dir"]),
            mtime=float(data["mtime"]),
            rule_id=str(data["rule_id"]),
            category=str(data["category"]),
            risk=str(data.get("risk", "low")),
        )


@dataclass
class ScanResult:
    scan_roots: list[Path]
    candidates: list[Candidate] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    overlaps_dropped: int = 0
    duration_seconds: float = 0.0

    @property
    def total_size(self) -> int:
        return sum(c.size_bytes for c in self.candidates)

    def by_category(self) -> dict[str, list[Candidate]]:
        grouped: dict[str, list[Candidate]] = {}
        for c in self.candidates:
            grouped.setdefault(c.category, []).append(c)
        return grouped

    def by_rule(self) -> dict[str, list[Candidate]]:
        grouped: dict[str, list[Candidate]] = {}
        for c in self.candidates:
            grouped.setdefault(c.rule_id, []).append(c)
        return grouped

    def to_dict(self) -> dict[str, Any]:
        return {
            "scan_roots": [str(r) for r in self.scan_roots],
            "total_size_bytes": self.total_size,
            "candidate_count": len(self.candidates),
            "overlaps_dropped": self.overlaps_dropped,
            "duration_seconds": round(self.duration_seconds, 3),
            "errors": list(self.errors),
            "categories": [
                {
                    "category": cat,
                    "count": len(items),
                    "size_bytes": sum(c.size_bytes for c in items),
                }
                for cat, items in sorted(
                    self.by_category().items(),
                    key=lambda kv: sum(c.size_bytes for c in kv[1]),
                    reverse=True,
                )
            ],
            "candidates": [c.to_dict() for c in self.candidates],
        }


@dataclass
class VolumeInfo:
    name: str
    path: Path
    total_bytes: int
    used_bytes: int
    free_bytes: int
    is_root: bool = False

    @property
    def percent_used(self) -> float:
        return (self.used_bytes / self.total_bytes * 100) if self.total_bytes else 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "path": str(self.path),
            "total_bytes": self.total_bytes,
            "used_bytes": self.used_bytes,
            "free_bytes": self.free_bytes,
            "percent_used": round(self.percent_used, 1),
            "is_root": self.is_root,
        }


@dataclass
class BackupInfo:
    udid: str
    path: Path
    device_name: str
    product_type: str
    last_backup_date: datetime | None
    size_bytes: int
    encrypted: bool

    def to_dict(self) -> dict[str, Any]:
        return {
            "udid": self.udid,
            "path": str(self.path),
            "device_name": self.device_name,
            "product_type": self.product_type,
            "last_backup_date": self.last_backup_date.isoformat() if self.last_backup_date else None,
            "size_bytes": self.size_bytes,
            "encrypted": self.encrypted,
        }


@dataclass
class DuplicateGroup:
    sha256: str
    size_bytes: int
    paths: list[Path]

    @property
    def wasted_bytes(self) -> int:
        return self.size_bytes * max(0, len(self.paths) - 1)

    def to_dict(self) -> dict[str, Any]:
        return {
            "sha256": self.sha256,
            "size_bytes": self.size_bytes,
            "wasted_bytes": self.wasted_bytes,
            "copies": len(self.paths),
            "paths": [str(p) for p in self.paths],
        }


@dataclass
class LargeFile:
    path: Path
    size_bytes: int
    mtime: float

    def to_dict(self) -> dict[str, Any]:
        return {"path": str(self.path), "size_bytes": self.size_bytes, "mtime": self.mtime}


@dataclass
class QuarantineEntry:
    id: int
    session_id: str
    original_path: str
    quarantine_path: str
    size_bytes: int
    mtime: float
    sha256: str | None
    rule_id: str
    category: str
    timestamp: str
    restored: bool = False
    purged: bool = False

    @property
    def is_available(self) -> bool:
        """True if the quarantined copy is currently reachable on disk
        (False e.g. when it sits on an external volume that is unmounted)."""
        try:
            return os.path.lexists(self.quarantine_path)
        except OSError:
            return False

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "session_id": self.session_id,
            "original_path": self.original_path,
            "quarantine_path": self.quarantine_path,
            "size_bytes": self.size_bytes,
            "mtime": self.mtime,
            "sha256": self.sha256,
            "rule_id": self.rule_id,
            "category": self.category,
            "timestamp": self.timestamp,
            "restored": self.restored,
            "purged": self.purged,
            "available": self.is_available,
        }


@dataclass
class SessionSummary:
    session_id: str
    count: int
    size_bytes: int
    first_timestamp: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class Skipped:
    """Why one item was left alone during a quarantine/restore/purge."""

    path: str
    reason: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ActionResult:
    """Outcome of a filesystem-mutating operation.

    Every mutating call returns one of these instead of raising midway, so
    a partially successful run still reports precisely what happened.
    """

    action: str
    entries: list[QuarantineEntry] = field(default_factory=list)
    skipped: list[Skipped] = field(default_factory=list)
    session_id: str | None = None

    @property
    def total_size(self) -> int:
        return sum(e.size_bytes for e in self.entries)

    def to_dict(self) -> dict[str, Any]:
        return {
            "action": self.action,
            "session_id": self.session_id,
            "count": len(self.entries),
            "total_size_bytes": self.total_size,
            "entries": [e.to_dict() for e in self.entries],
            "skipped": [s.to_dict() for s in self.skipped],
        }


@dataclass
class OrganizeMove:
    """A proposed reorganize move (see ``organize.propose_moves``) — not
    yet applied. ``reason`` explains how the category was chosen:
    ``"extension"`` (a confident prior), ``"classifier"`` (the learned
    model, see ``classify.py``), ``"cluster: <name>"`` (project grouping),
    or ``"date"``."""

    path: Path
    category: str
    destination: Path
    confidence: float
    reason: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": str(self.path),
            "category": self.category,
            "destination": str(self.destination),
            "confidence": round(self.confidence, 3),
            "reason": self.reason,
        }


@dataclass
class OrganizeEntry:
    """One applied reorganize move, recorded so ``organize undo`` can
    reverse it later."""

    id: int
    session_id: str
    original_path: str
    new_path: str
    category: str
    timestamp: str
    undone: bool = False

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class OrganizeResult:
    entries: list[OrganizeEntry] = field(default_factory=list)
    skipped: list[Skipped] = field(default_factory=list)
    session_id: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "session_id": self.session_id,
            "count": len(self.entries),
            "entries": [e.to_dict() for e in self.entries],
            "skipped": [s.to_dict() for s in self.skipped],
        }
