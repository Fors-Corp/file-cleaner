"""Cleanup plans: review-then-apply, with nothing changing in between.

``fclean clean`` without ``--apply`` shows a dry run; historically a later
``--apply`` re-scanned and could quarantine something that appeared in the
meantime and was therefore never reviewed. A *plan file* closes that gap:

    fclean clean --save-plan plan.json      # review this exact list
    fclean apply plan.json                  # move exactly these, nothing else

On apply every item is re-validated: it must still exist, still be the same
kind (file/dir), and — for files — have the same size and mtime it had when
the plan was written. Anything that changed is skipped and reported.
"""

from __future__ import annotations

import contextlib
import json
import os
import stat as stat_mod
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from filecleaner import __version__
from filecleaner import scanner as scanner_mod
from filecleaner.models import Candidate, ScanResult, Skipped

PLAN_FORMAT_VERSION = 1


class PlanError(Exception):
    """The plan file is unreadable or was written by an incompatible version."""


@dataclass
class CleanupPlan:
    created_at: str
    scan_roots: list[Path]
    candidates: list[Candidate]
    tool_version: str = __version__
    format_version: int = PLAN_FORMAT_VERSION
    note: str = ""
    extra: dict[str, Any] = field(default_factory=dict)

    @property
    def total_size(self) -> int:
        return sum(c.size_bytes for c in self.candidates)

    def to_dict(self) -> dict[str, Any]:
        return {
            "format_version": self.format_version,
            "tool_version": self.tool_version,
            "created_at": self.created_at,
            "note": self.note,
            "scan_roots": [str(r) for r in self.scan_roots],
            "total_size_bytes": self.total_size,
            "candidate_count": len(self.candidates),
            "candidates": [c.to_dict() for c in self.candidates],
        }

    @classmethod
    def from_scan(cls, result: ScanResult, *, note: str = "") -> CleanupPlan:
        return cls(
            created_at=datetime.now(UTC).isoformat(timespec="seconds"),
            scan_roots=list(result.scan_roots),
            candidates=list(result.candidates),
            note=note,
        )

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> CleanupPlan:
        version = data.get("format_version")
        if version != PLAN_FORMAT_VERSION:
            raise PlanError(f"unsupported plan format_version {version!r} (expected {PLAN_FORMAT_VERSION})")
        try:
            candidates = [Candidate.from_dict(c) for c in data["candidates"]]
            roots = [Path(str(r)) for r in data.get("scan_roots", [])]
        except (KeyError, TypeError, ValueError) as exc:
            raise PlanError(f"malformed plan file: {exc}") from exc
        return cls(
            created_at=str(data.get("created_at", "")),
            scan_roots=roots,
            candidates=candidates,
            tool_version=str(data.get("tool_version", "")),
            format_version=int(version),
            note=str(data.get("note", "")),
        )


def save_plan(plan: CleanupPlan, path: Path) -> None:
    path = path.expanduser()
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(json.dumps(plan.to_dict(), indent=2) + "\n", encoding="utf-8")
    with contextlib.suppress(OSError):
        os.chmod(tmp, 0o600)
    os.replace(tmp, path)


def load_plan(path: Path) -> CleanupPlan:
    path = path.expanduser()
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise PlanError(f"cannot read {path}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise PlanError(f"{path} is not valid JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise PlanError(f"{path}: expected a JSON object")
    return CleanupPlan.from_dict(data)


def revalidate(plan: CleanupPlan) -> tuple[list[Candidate], list[Skipped]]:
    """Split a plan into items still safe to apply and items that changed."""
    fresh: list[Candidate] = []
    stale: list[Skipped] = []
    for cand in plan.candidates:
        try:
            st = os.lstat(cand.path)
        except FileNotFoundError:
            stale.append(Skipped(str(cand.path), "no longer exists"))
            continue
        except OSError as exc:
            stale.append(Skipped(str(cand.path), f"cannot stat: {exc.strerror or exc}"))
            continue

        if stat_mod.S_ISLNK(st.st_mode):
            stale.append(Skipped(str(cand.path), "is now a symlink"))
            continue
        is_dir = stat_mod.S_ISDIR(st.st_mode)
        if is_dir != cand.is_dir:
            stale.append(Skipped(str(cand.path), "changed between file and directory"))
            continue
        if is_dir:
            # A directory candidate's size/mtime describe everything inside
            # it, recursively — re-derive the same numbers the same way the
            # scanner did, so content added/changed/removed since the plan
            # was written is caught, not just changes to the top folder.
            # (An adversarially backdated mtime with a coincidentally
            # unchanged total size could in principle slip through; real
            # cache/log directories never do this, and it's still bounded
            # by every other safety check purge/quarantine already apply.)
            size, newest_inside = scanner_mod.dir_stats(cand.path)
            changed = size != cand.size_bytes or max(st.st_mtime, newest_inside) > cand.mtime + 1e-6
        else:
            changed = st.st_size != cand.size_bytes or abs(st.st_mtime - cand.mtime) > 1e-6
        if changed:
            stale.append(Skipped(str(cand.path), "modified since the plan was written"))
            continue
        fresh.append(cand)
    return fresh, stale
