from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path


@dataclass(frozen=True)
class Rule:
    id: str
    label: str
    category: str
    description: str
    enabled_by_default: bool
    risk: str  # "low" | "medium"
    kind: str  # "file" | "dir" — whether matches are individual files or whole directories
    scope: str  # "home" | "root" | "each_volume"
    include_globs: tuple[str, ...]
    exclude_globs: tuple[str, ...] = ()
    min_age_days: int = 0
    min_size_bytes: int = 0
    source: str = "builtin"  # "builtin" | "custom"


@dataclass
class Candidate:
    path: Path
    size_bytes: int
    is_dir: bool
    mtime: float
    rule_id: str
    category: str
    risk: str


@dataclass
class ScanResult:
    scan_roots: list[Path]
    candidates: list[Candidate] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    @property
    def total_size(self) -> int:
        return sum(c.size_bytes for c in self.candidates)

    def by_category(self) -> dict[str, list[Candidate]]:
        grouped: dict[str, list[Candidate]] = {}
        for c in self.candidates:
            grouped.setdefault(c.category, []).append(c)
        return grouped


@dataclass
class VolumeInfo:
    name: str
    path: Path
    total_bytes: int
    used_bytes: int
    free_bytes: int
    is_root: bool = False


@dataclass
class BackupInfo:
    udid: str
    path: Path
    device_name: str
    product_type: str
    last_backup_date: datetime | None
    size_bytes: int
    encrypted: bool


@dataclass
class DuplicateGroup:
    sha256: str
    size_bytes: int
    paths: list[Path]

    @property
    def wasted_bytes(self) -> int:
        return self.size_bytes * max(0, len(self.paths) - 1)


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
