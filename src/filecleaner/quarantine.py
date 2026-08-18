"""The quarantine system: filecleaner's "strong backup" safety net.

`clean --apply` never deletes anything directly. It *moves* matched files
into a per-session folder under the quarantine directory (an ordinary
same-volume rename in the common case — instant, no extra free space
needed) and records exactly where each item came from in a local SQLite
manifest. Nothing is permanently removed until an explicit, separate
`purge` call.
"""

from __future__ import annotations

import hashlib
import os
import secrets
import shutil
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from filecleaner import audit
from filecleaner import config as config_mod
from filecleaner import safety
from filecleaner.models import Candidate, QuarantineEntry

_SCHEMA = """
CREATE TABLE IF NOT EXISTS quarantine_entries (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id TEXT NOT NULL,
    original_path TEXT NOT NULL,
    quarantine_path TEXT NOT NULL,
    size_bytes INTEGER NOT NULL,
    mtime REAL NOT NULL,
    sha256 TEXT,
    rule_id TEXT NOT NULL,
    category TEXT NOT NULL,
    timestamp TEXT NOT NULL,
    restored INTEGER NOT NULL DEFAULT 0,
    purged INTEGER NOT NULL DEFAULT 0
)
"""

_HASH_CHUNK = 1024 * 1024


def _connect(config: dict[str, Any]) -> sqlite3.Connection:
    db_path = config_mod.get_manifest_db_path(config)
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    conn.execute(_SCHEMA)
    conn.commit()
    try:
        db_path.chmod(0o600)
    except OSError:
        pass
    return conn


def new_session_id() -> str:
    return datetime.now().strftime("%Y%m%d-%H%M%S-") + secrets.token_hex(3)


def _hash_file(path: Path, max_bytes: int) -> str | None:
    try:
        if path.stat().st_size > max_bytes:
            return None
    except OSError:
        return None
    digest = hashlib.sha256()
    try:
        with path.open("rb") as f:
            while chunk := f.read(_HASH_CHUNK):
                digest.update(chunk)
    except OSError:
        return None
    return digest.hexdigest()


_OVERWRITE_CHUNK = 1024 * 1024


def _secure_overwrite_file(path: Path) -> None:
    """Best-effort overwrite of a file's bytes before deletion.

    NOTE: on SSD/flash storage (this machine's disk) the filesystem may not
    write in place — wear-leveling and the flash translation layer mean the
    physical NAND cells holding the original data are not guaranteed to be
    the ones overwritten. This is belt-and-suspenders, not a cryptographic
    guarantee; if FileVault is on, the data is already unreadable the
    instant it's deleted regardless of this step.
    """
    try:
        size = path.stat().st_size
    except OSError:
        return
    try:
        with path.open("r+b") as f:
            remaining = size
            while remaining > 0:
                chunk = min(_OVERWRITE_CHUNK, remaining)
                f.write(secrets.token_bytes(chunk))
                remaining -= chunk
            f.flush()
            os.fsync(f.fileno())
    except OSError:
        pass


def _secure_overwrite_tree(path: Path) -> None:
    if path.is_symlink():
        return
    if path.is_file():
        _secure_overwrite_file(path)
        return
    if path.is_dir():
        for root, _dirs, files in os.walk(path, followlinks=False):
            for filename in files:
                file_path = Path(root) / filename
                if not file_path.is_symlink():
                    _secure_overwrite_file(file_path)


def _row_to_entry(row: sqlite3.Row) -> QuarantineEntry:
    return QuarantineEntry(
        id=row["id"],
        session_id=row["session_id"],
        original_path=row["original_path"],
        quarantine_path=row["quarantine_path"],
        size_bytes=row["size_bytes"],
        mtime=row["mtime"],
        sha256=row["sha256"],
        rule_id=row["rule_id"],
        category=row["category"],
        timestamp=row["timestamp"],
        restored=bool(row["restored"]),
        purged=bool(row["purged"]),
    )


def quarantine_candidates(
    candidates: list[Candidate],
    config: dict[str, Any],
    *,
    session_id: str | None = None,
) -> list[QuarantineEntry]:
    session_id = session_id or new_session_id()
    quarantine_dir = config_mod.get_quarantine_dir(config)
    session_dir = quarantine_dir / session_id
    max_hash_bytes = config.get("hash_duplicates_max_bytes", 2_000_000_000)
    extra_protected = config_mod.extra_protected_paths(config)

    conn = _connect(config)
    entries: list[QuarantineEntry] = []
    try:
        for cand in candidates:
            original = cand.path.resolve(strict=False)

            # Belt-and-braces: re-check the deny-list right before the move,
            # not just at scan time.
            if safety.is_protected(original, extra_protected=extra_protected):
                continue
            if not original.exists():
                continue

            rel = Path(*original.parts[1:]) if original.is_absolute() else original
            dest = session_dir / rel
            dest.parent.mkdir(parents=True, exist_ok=True)

            sha256 = None if cand.is_dir else _hash_file(original, max_hash_bytes)

            try:
                shutil.move(str(original), str(dest))
            except OSError as exc:
                audit.log_action("quarantine_error", {"path": str(original), "error": str(exc)})
                continue

            timestamp = datetime.now(timezone.utc).isoformat()
            cursor = conn.execute(
                "INSERT INTO quarantine_entries "
                "(session_id, original_path, quarantine_path, size_bytes, mtime, sha256, "
                "rule_id, category, timestamp) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    session_id,
                    str(original),
                    str(dest),
                    cand.size_bytes,
                    cand.mtime,
                    sha256,
                    cand.rule_id,
                    cand.category,
                    timestamp,
                ),
            )
            conn.commit()
            entries.append(
                QuarantineEntry(
                    id=cursor.lastrowid,
                    session_id=session_id,
                    original_path=str(original),
                    quarantine_path=str(dest),
                    size_bytes=cand.size_bytes,
                    mtime=cand.mtime,
                    sha256=sha256,
                    rule_id=cand.rule_id,
                    category=cand.category,
                    timestamp=timestamp,
                )
            )
            audit.log_action(
                "quarantine",
                {
                    "path": str(original),
                    "size_bytes": cand.size_bytes,
                    "rule_id": cand.rule_id,
                    "session_id": session_id,
                },
            )
    finally:
        conn.close()
    return entries


def list_entries(
    config: dict[str, Any],
    *,
    session_id: str | None = None,
    include_restored: bool = False,
    include_purged: bool = False,
) -> list[QuarantineEntry]:
    conn = _connect(config)
    try:
        query = "SELECT * FROM quarantine_entries WHERE 1=1"
        params: list[Any] = []
        if session_id:
            query += " AND session_id = ?"
            params.append(session_id)
        if not include_restored:
            query += " AND restored = 0"
        if not include_purged:
            query += " AND purged = 0"
        query += " ORDER BY timestamp DESC"
        rows = conn.execute(query, params).fetchall()
    finally:
        conn.close()
    return [_row_to_entry(r) for r in rows]


def restore_entries(entry_ids: list[int], config: dict[str, Any]) -> list[QuarantineEntry]:
    conn = _connect(config)
    restored: list[QuarantineEntry] = []
    try:
        for eid in entry_ids:
            row = conn.execute("SELECT * FROM quarantine_entries WHERE id = ?", (eid,)).fetchone()
            if row is None or row["restored"] or row["purged"]:
                continue
            entry = _row_to_entry(row)
            src = Path(entry.quarantine_path)
            dst = Path(entry.original_path)
            if not src.exists():
                continue
            dst.parent.mkdir(parents=True, exist_ok=True)
            if dst.exists():
                # Never silently overwrite something that now occupies the
                # original spot — restore alongside it instead.
                dst = dst.with_name(dst.name + f".restored-{entry.id}")
            shutil.move(str(src), str(dst))
            conn.execute("UPDATE quarantine_entries SET restored = 1 WHERE id = ?", (eid,))
            conn.commit()
            restored.append(entry)
            audit.log_action(
                "restore",
                {"path": entry.original_path, "restored_to": str(dst), "session_id": entry.session_id},
            )
    finally:
        conn.close()
    return restored


def purge_entries(
    entry_ids: list[int],
    config: dict[str, Any],
    *,
    secure: bool = False,
) -> list[QuarantineEntry]:
    conn = _connect(config)
    purged: list[QuarantineEntry] = []
    extra_protected = config_mod.extra_protected_paths(config)
    try:
        for eid in entry_ids:
            row = conn.execute("SELECT * FROM quarantine_entries WHERE id = ?", (eid,)).fetchone()
            if row is None or row["purged"]:
                continue
            entry = _row_to_entry(row)
            target = Path(entry.quarantine_path)
            if safety.is_protected(target, extra_protected=extra_protected):
                continue
            try:
                if secure:
                    _secure_overwrite_tree(target)
                if target.is_symlink():
                    target.unlink()
                elif target.is_dir():
                    shutil.rmtree(target)
                elif target.exists():
                    target.unlink()
            except OSError as exc:
                audit.log_action("purge_error", {"path": str(target), "error": str(exc)})
                continue
            conn.execute("UPDATE quarantine_entries SET purged = 1 WHERE id = ?", (eid,))
            conn.commit()
            purged.append(entry)
            audit.log_action(
                "purge",
                {
                    "path": entry.original_path,
                    "size_bytes": entry.size_bytes,
                    "session_id": entry.session_id,
                    "secure": secure,
                },
            )
    finally:
        conn.close()
    return purged


def eligible_for_purge(config: dict[str, Any]) -> list[QuarantineEntry]:
    retention_days = config.get("retention_days", 30)
    cutoff = datetime.now(timezone.utc).timestamp() - retention_days * 86400
    eligible = []
    for entry in list_entries(config):
        ts = datetime.fromisoformat(entry.timestamp).timestamp()
        if ts <= cutoff:
            eligible.append(entry)
    return eligible


def quarantine_summary(config: dict[str, Any]) -> tuple[int, int]:
    entries = list_entries(config)
    return len(entries), sum(e.size_bytes for e in entries)
