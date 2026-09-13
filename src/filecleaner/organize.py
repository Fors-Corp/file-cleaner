"""Smart folder reorganization: propose where loose files in a folder
should live, then (only on explicit request) move them there.

Only files directly inside the given root are ever considered — existing
subfolders are never touched or descended into, so a user's own manual
organization is left exactly as it is. Three signals decide a file's
category, in order: (1) project clustering, when two or more files share a
cleaned-up base name (``report.docx`` + ``report_v2.docx``) they land
together in ``Projects/<name>/`` regardless of type; (2) a confident
extension prior (``.pdf`` -> Documents); (3) the local learned classifier
(``classify.py``) for anything else, with its confidence surfaced so a
low-confidence guess can be flagged for review rather than silently acted
on.

Like ``clean``, this is dry-run by default: ``propose_moves`` never touches
the filesystem, only ``apply_moves`` does — and every applied move is
recorded (in the same local manifest database quarantine uses, see
``quarantine.open_manifest_db``) so ``undo_session`` can put everything
back.
"""

from __future__ import annotations

import re
import secrets
import shutil
import sqlite3
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from filecleaner import audit, classify, safety
from filecleaner import config as config_mod
from filecleaner import quarantine as quarantine_mod
from filecleaner.models import OrganizeEntry, OrganizeMove, OrganizeResult, Skipped

_SCHEMA = """
CREATE TABLE IF NOT EXISTS organize_moves (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id TEXT NOT NULL,
    original_path TEXT NOT NULL,
    new_path TEXT NOT NULL,
    category TEXT NOT NULL,
    timestamp TEXT NOT NULL,
    undone INTEGER NOT NULL DEFAULT 0
)
"""
_INDEXES = ("CREATE INDEX IF NOT EXISTS idx_organize_session ON organize_moves(session_id)",)

_SKIP_NAMES = frozenset({".DS_Store"})
_MODES = ("type", "date", "date-only")
_DEFAULT_CONFIDENCE_THRESHOLD = 0.5

# Only ever strips an explicit "this is a duplicate/version" marker after a
# separator — never a bare trailing number, since that would wrongly merge
# unrelated sequentially-named files (camera exports like IMG_1234.jpg,
# IMG_1235.jpg) into one fake "project".
_CLUSTER_SUFFIX_RE = re.compile(
    r"[\s_\-]+(copy(?:\s*\d+)?|v\d+|version\s*\d+|final|draft|\(\d+\))$", re.IGNORECASE
)

# macOS's default screenshot filenames: "Screenshot 2026-09-13 at 10.32.45 AM.png"
# (current) and "Screen Shot 2026-09-13 at 10.32.45 AM.png" (older macOS).
_SCREENSHOT_RE = re.compile(r"^screen\s?shot\s+\d{4}-\d{2}-\d{2}\s+at\s+", re.IGNORECASE)


def _is_screenshot(name: str) -> bool:
    return bool(_SCREENSHOT_RE.match(name))


class OrganizeError(Exception):
    """An invalid mode or session id was given."""


def _cluster_key(stem: str) -> str:
    cleaned = stem
    while True:
        stripped = _CLUSTER_SUFFIX_RE.sub("", cleaned).strip()
        if stripped == cleaned:
            break
        cleaned = stripped
    return (cleaned or stem).lower()


def _date_bucket(mtime: float) -> str:
    dt = datetime.fromtimestamp(mtime)
    return f"{dt.year:04d}/{dt.month:02d}"


def propose_moves(
    root: Path,
    config: dict[str, Any],
    *,
    mode: str = "type",
    cluster_projects: bool = True,
    classifier: classify.Classifier | None = None,
    confidence_threshold: float = _DEFAULT_CONFIDENCE_THRESHOLD,
) -> list[OrganizeMove]:
    """Propose where each loose top-level file in ``root`` should move.
    Read-only — never touches the filesystem. See ``apply_moves``."""
    if mode not in _MODES:
        raise OrganizeError(f"unknown mode {mode!r}; expected one of {_MODES}")

    root = root.expanduser().resolve()
    extra_protected = config_mod.extra_protected_paths(config) + config_mod.data_paths_to_protect(config)
    clf = classifier if classifier is not None else classify.load()

    try:
        entries = sorted(root.iterdir())
    except OSError:
        return []

    reserved_names = set(classify.CATEGORIES) | {"Projects"}
    candidates: list[Path] = []
    for entry in entries:
        if entry.name in _SKIP_NAMES or entry.name.startswith("."):
            continue
        if entry.is_symlink() or not entry.is_file():
            continue
        if entry.name in reserved_names:
            continue
        if safety.is_protected(entry, extra_protected=extra_protected):
            continue
        candidates.append(entry)

    moves: list[OrganizeMove] = []
    clustered: set[Path] = set()

    if cluster_projects:
        groups: dict[str, list[Path]] = {}
        for path in candidates:
            key = _cluster_key(path.stem)
            if len(key) < 3:
                continue
            groups.setdefault(key, []).append(path)
        for key, members in groups.items():
            if len(members) < 2:
                continue
            dest_dir = root / "Projects" / key
            for member in members:
                moves.append(
                    OrganizeMove(
                        path=member,
                        category="Projects",
                        destination=dest_dir / member.name,
                        confidence=1.0,
                        reason=f"cluster: {key}",
                    )
                )
                clustered.add(member)

    for path in candidates:
        if path in clustered:
            continue
        if _is_screenshot(path.name):
            category, confidence, reason = "Screenshots", 1.0, "screenshot"
        else:
            ext = path.suffix.lower().lstrip(".")
            if ext in classify.EXTENSION_PRIORS:
                category, confidence, reason = classify.EXTENSION_PRIORS[ext], 1.0, "extension"
            else:
                category, confidence = clf.predict(path)
                reason = "classifier"
        if confidence < confidence_threshold:
            reason = f"{reason} (low confidence, review)"

        try:
            mtime = path.stat().st_mtime
        except OSError:
            mtime = 0.0

        if mode == "type":
            dest_dir = root / category
        elif mode == "date":
            dest_dir = root / category / _date_bucket(mtime)
        else:  # date-only
            dest_dir = root / _date_bucket(mtime)
            reason = "date"

        moves.append(
            OrganizeMove(
                path=path, category=category, destination=dest_dir / path.name, confidence=confidence, reason=reason
            )
        )

    return moves


def _connect(config: dict[str, Any]) -> sqlite3.Connection:
    return quarantine_mod.open_manifest_db(config, schema=_SCHEMA, indexes=_INDEXES)


def new_session_id() -> str:
    return datetime.now().strftime("%Y%m%d-%H%M%S-") + secrets.token_hex(3)


def list_sessions(config: dict[str, Any]) -> list[dict[str, Any]]:
    """One row per ``organize --apply`` run: how many files moved, how many
    of those are still in their new location (not undone), and when."""
    conn = _connect(config)
    try:
        rows = conn.execute(
            "SELECT session_id, COUNT(*) as n, MIN(timestamp) as first_ts, "
            "SUM(CASE WHEN undone = 0 THEN 1 ELSE 0 END) as active "
            "FROM organize_moves GROUP BY session_id ORDER BY first_ts DESC"
        ).fetchall()
    finally:
        conn.close()
    return [
        {"session_id": r["session_id"], "count": r["n"], "active": r["active"], "first_timestamp": r["first_ts"]}
        for r in rows
    ]


def apply_moves(moves: list[OrganizeMove], config: dict[str, Any], *, session_id: str | None = None) -> OrganizeResult:
    """Move every proposed file to its destination and record it, so
    ``undo_session`` can reverse it later. Never overwrites an existing
    file at the destination."""
    session_id = session_id or new_session_id()
    result = OrganizeResult(session_id=session_id)
    conn = _connect(config)
    try:
        for move in moves:
            original = move.path
            if not original.exists():
                result.skipped.append(Skipped(str(original), "no longer exists"))
                continue
            if move.destination.exists():
                result.skipped.append(Skipped(str(original), "destination already exists"))
                continue
            try:
                move.destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.move(str(original), str(move.destination))
            except OSError as exc:
                result.skipped.append(Skipped(str(original), f"move failed: {exc.strerror or exc}"))
                continue

            timestamp = datetime.now(UTC).isoformat()
            cursor = conn.execute(
                "INSERT INTO organize_moves (session_id, original_path, new_path, category, timestamp) "
                "VALUES (?, ?, ?, ?, ?)",
                (session_id, str(original), str(move.destination), move.category, timestamp),
            )
            conn.commit()
            assert cursor.lastrowid is not None
            result.entries.append(
                OrganizeEntry(
                    id=cursor.lastrowid,
                    session_id=session_id,
                    original_path=str(original),
                    new_path=str(move.destination),
                    category=move.category,
                    timestamp=timestamp,
                )
            )
            audit.log_action(
                "organize",
                {
                    "path": str(original),
                    "new_path": str(move.destination),
                    "category": move.category,
                    "session_id": session_id,
                },
            )
    finally:
        conn.close()
    return result


def undo_session(session_id: str, config: dict[str, Any]) -> OrganizeResult:
    """Move everything from one ``organize --apply`` session back to where
    it came from. Skips (never overwrites) anything already restored, no
    longer where it was left, or whose original location is now occupied."""
    conn = _connect(config)
    result = OrganizeResult(session_id=session_id)
    try:
        rows = conn.execute(
            "SELECT * FROM organize_moves WHERE session_id = ? AND undone = 0", (session_id,)
        ).fetchall()
        for row in rows:
            new_path = Path(row["new_path"])
            original_path = Path(row["original_path"])
            if not new_path.exists():
                result.skipped.append(Skipped(row["new_path"], "no longer exists"))
                continue
            if original_path.exists():
                result.skipped.append(Skipped(row["new_path"], "original location now occupied"))
                continue
            try:
                original_path.parent.mkdir(parents=True, exist_ok=True)
                shutil.move(str(new_path), str(original_path))
            except OSError as exc:
                result.skipped.append(Skipped(row["new_path"], f"move failed: {exc.strerror or exc}"))
                continue

            conn.execute("UPDATE organize_moves SET undone = 1 WHERE id = ?", (row["id"],))
            conn.commit()
            result.entries.append(
                OrganizeEntry(
                    id=row["id"],
                    session_id=session_id,
                    original_path=row["original_path"],
                    new_path=row["new_path"],
                    category=row["category"],
                    timestamp=row["timestamp"],
                    undone=True,
                )
            )
            audit.log_action(
                "organize_undo",
                {"path": row["new_path"], "restored_to": row["original_path"], "session_id": session_id},
            )
    finally:
        conn.close()
    if not result.entries and not result.skipped:
        raise OrganizeError(f"no such organize session: {session_id!r}")
    return result
