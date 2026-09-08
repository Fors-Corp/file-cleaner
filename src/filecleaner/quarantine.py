"""The quarantine system: File Cleaner's "strong backup" safety net.

`clean --apply` never deletes anything directly. It *moves* matched files
into a per-session folder and records exactly where each item came from in
a local SQLite manifest. Nothing is permanently removed until an explicit,
separate `purge` call.

Cross-volume moves are avoided where possible: if a candidate lives on a
different filesystem than the configured quarantine directory and
``volume_local_quarantine`` is enabled, it is quarantined into a hidden
folder at the root of *that same volume* instead — still an instant
same-device rename, no copy, and it still works if the drive is later
unplugged (the manifest simply reports it as unavailable, not restored).
"""

from __future__ import annotations

import contextlib
import hashlib
import os
import secrets
import shutil
import sqlite3
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from filecleaner import audit, safety
from filecleaner import config as config_mod
from filecleaner import volumes as volumes_mod
from filecleaner.models import ActionResult, Candidate, QuarantineEntry, SessionSummary, Skipped

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
_INDEXES = (
    "CREATE INDEX IF NOT EXISTS idx_session ON quarantine_entries(session_id)",
    "CREATE INDEX IF NOT EXISTS idx_timestamp ON quarantine_entries(timestamp)",
)

_HASH_CHUNK = 1024 * 1024
_OVERWRITE_CHUNK = 1024 * 1024


def _connect(config: dict[str, Any]) -> sqlite3.Connection:
    db_path = config_mod.get_manifest_db_path(config)
    conn = sqlite3.connect(db_path, timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute(_SCHEMA)
    for stmt in _INDEXES:
        conn.execute(stmt)
    conn.commit()
    with contextlib.suppress(OSError):
        db_path.chmod(0o600)
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


def _secure_overwrite_file(path: Path) -> None:
    """Best-effort overwrite of a file's bytes before deletion.

    NOTE: on SSD/flash storage the filesystem may not write in place —
    wear-leveling and the flash translation layer mean the physical NAND
    cells holding the original data are not guaranteed to be the ones
    overwritten. This is belt-and-suspenders, not a cryptographic
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


def _session_root(original: Path, session_id: str, config: dict[str, Any]) -> Path:
    """Where to put this one item's session folder: the configured
    quarantine dir, unless a same-volume alternative is enabled and the
    item lives elsewhere."""
    primary = config_mod.get_quarantine_dir(config)
    if not config.get("volume_local_quarantine", True):
        return primary / session_id
    if volumes_mod.same_filesystem(original, primary):
        return primary / session_id
    mount_point = volumes_mod.mount_point_for(original)
    local_root = mount_point / config_mod.VOLUME_QUARANTINE_DIRNAME
    try:
        local_root.mkdir(parents=True, exist_ok=True)
        os.chmod(local_root, 0o700)
    except OSError:
        return primary / session_id  # e.g. read-only volume: fall back
    return local_root / session_id


def quarantine_candidates(
    candidates: list[Candidate],
    config: dict[str, Any],
    *,
    session_id: str | None = None,
    allowed_roots: tuple[Path, ...] = (),
) -> ActionResult:
    """Move every candidate into quarantine and record it in the manifest.

    ``allowed_roots``, when given, is a defense-in-depth check: a candidate
    whose resolved path does not live under any of these roots is skipped
    rather than moved — it guards against acting on a stale plan or a
    candidate list that was ever tampered with after a scan.
    """
    session_id = session_id or new_session_id()
    max_hash_bytes = config.get("hash_duplicates_max_bytes", 2_000_000_000)
    extra_protected = config_mod.extra_protected_paths(config) + config_mod.data_paths_to_protect(config)

    result = ActionResult(action="quarantine", session_id=session_id)
    conn = _connect(config)
    try:
        for cand in candidates:
            original = cand.path.resolve(strict=False)

            if allowed_roots and not safety.is_within_allowed_roots(original, allowed_roots):
                result.skipped.append(Skipped(str(original), "outside the roots that were scanned"))
                continue
            # Belt-and-braces: re-check the deny-list right before the move,
            # not just at scan time.
            if safety.is_protected(original, extra_protected=extra_protected):
                result.skipped.append(Skipped(str(original), "protected path"))
                continue
            if not original.exists():
                result.skipped.append(Skipped(str(original), "no longer exists"))
                continue

            session_dir = _session_root(original, session_id, config)
            rel = Path(*original.parts[1:]) if original.is_absolute() else original
            dest = session_dir / rel
            try:
                dest.parent.mkdir(parents=True, exist_ok=True)
            except OSError as exc:
                result.skipped.append(Skipped(str(original), f"cannot prepare quarantine folder: {exc}"))
                continue

            sha256 = None if cand.is_dir else _hash_file(original, max_hash_bytes)

            try:
                shutil.move(str(original), str(dest))
            except OSError as exc:
                result.skipped.append(Skipped(str(original), f"move failed: {exc.strerror or exc}"))
                audit.log_action("quarantine_error", {"path": str(original), "error": str(exc)})
                continue

            timestamp = datetime.now(UTC).isoformat()
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
            # AUTOINCREMENT guarantees a row id after a successful INSERT;
            # sqlite3's stub types lastrowid as int | None only because it's
            # also None before any insert happens on this cursor.
            assert cursor.lastrowid is not None
            result.entries.append(
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
    return result


def list_entries(
    config: dict[str, Any],
    *,
    session_id: str | None = None,
    include_restored: bool = False,
    include_purged: bool = False,
    path_contains: str | None = None,
    ids: tuple[int, ...] | None = None,
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
        if path_contains:
            query += " AND original_path LIKE ?"
            params.append(f"%{path_contains}%")
        if ids is not None:
            if not ids:
                return []
            query += f" AND id IN ({','.join('?' * len(ids))})"
            params.extend(ids)
        query += " ORDER BY timestamp DESC"
        rows = conn.execute(query, params).fetchall()
    finally:
        conn.close()
    return [_row_to_entry(r) for r in rows]


def list_sessions(config: dict[str, Any]) -> list[SessionSummary]:
    conn = _connect(config)
    try:
        rows = conn.execute(
            "SELECT session_id, COUNT(*) as n, SUM(size_bytes) as total, MIN(timestamp) as first_ts "
            "FROM quarantine_entries WHERE restored = 0 AND purged = 0 "
            "GROUP BY session_id ORDER BY first_ts DESC"
        ).fetchall()
    finally:
        conn.close()
    return [
        SessionSummary(session_id=r["session_id"], count=r["n"], size_bytes=r["total"] or 0, first_timestamp=r["first_ts"])
        for r in rows
    ]


def restore_entries(entry_ids: list[int], config: dict[str, Any]) -> ActionResult:
    conn = _connect(config)
    result = ActionResult(action="restore")
    # Restore writes back to `original_path`, which every entry got from our
    # own scan-time safety check — but a manifest can outlive a config change
    # (e.g. a path added to `protected_paths` after something was already
    # quarantined), so re-check the destination too, defense in depth.
    extra_protected = config_mod.extra_protected_paths(config)
    try:
        for eid in entry_ids:
            row = conn.execute("SELECT * FROM quarantine_entries WHERE id = ?", (eid,)).fetchone()
            if row is None:
                result.skipped.append(Skipped(f"id {eid}", "no such quarantine entry"))
                continue
            entry = _row_to_entry(row)
            if entry.restored or entry.purged:
                result.skipped.append(Skipped(entry.original_path, "already restored or purged"))
                continue
            src = Path(entry.quarantine_path)
            dst = Path(entry.original_path)
            if safety.is_protected(dst, extra_protected=extra_protected):
                result.skipped.append(Skipped(entry.original_path, "restoring here is no longer allowed"))
                continue
            if not src.exists():
                result.skipped.append(Skipped(entry.original_path, "quarantined copy is missing (unmounted volume?)"))
                continue
            try:
                dst.parent.mkdir(parents=True, exist_ok=True)
            except OSError as exc:
                result.skipped.append(Skipped(entry.original_path, f"cannot recreate parent folder: {exc}"))
                continue
            if dst.exists():
                # Never silently overwrite something that now occupies the
                # original spot — restore alongside it instead.
                dst = dst.with_name(dst.name + f".restored-{entry.id}")
            try:
                shutil.move(str(src), str(dst))
            except OSError as exc:
                result.skipped.append(Skipped(entry.original_path, f"restore failed: {exc.strerror or exc}"))
                continue
            conn.execute("UPDATE quarantine_entries SET restored = 1 WHERE id = ?", (eid,))
            conn.commit()
            entry.restored = True
            result.entries.append(entry)
            audit.log_action(
                "restore",
                {"path": entry.original_path, "restored_to": str(dst), "session_id": entry.session_id},
            )
    finally:
        conn.close()
    return result


def purge_entries(
    entry_ids: list[int],
    config: dict[str, Any],
    *,
    secure: bool = False,
) -> ActionResult:
    conn = _connect(config)
    result = ActionResult(action="purge")
    # NOTE: deliberately *not* config_mod.data_paths_to_protect() here — that
    # includes the quarantine directory itself, which is exactly where every
    # legitimate purge target lives. Only the user's own `config keep` list
    # (plus safety.py's hardcoded system/self deny-list, always applied) is
    # relevant when the thing being deleted already sits inside quarantine.
    extra_protected = config_mod.extra_protected_paths(config)
    try:
        for eid in entry_ids:
            row = conn.execute("SELECT * FROM quarantine_entries WHERE id = ?", (eid,)).fetchone()
            if row is None:
                result.skipped.append(Skipped(f"id {eid}", "no such quarantine entry"))
                continue
            entry = _row_to_entry(row)
            if entry.purged:
                result.skipped.append(Skipped(entry.original_path, "already purged"))
                continue
            target = Path(entry.quarantine_path)
            if safety.is_protected(target, extra_protected=extra_protected):
                result.skipped.append(Skipped(entry.original_path, "protected path"))
                continue
            try:
                if not target.exists() and not target.is_symlink():
                    pass  # already gone on disk; still mark purged so the manifest stays accurate
                elif secure:
                    _secure_overwrite_tree(target)
                if target.is_symlink():
                    target.unlink()
                elif target.is_dir():
                    shutil.rmtree(target)
                elif target.exists():
                    target.unlink()
            except OSError as exc:
                result.skipped.append(Skipped(entry.original_path, f"delete failed: {exc.strerror or exc}"))
                audit.log_action("purge_error", {"path": str(target), "error": str(exc)})
                continue
            conn.execute("UPDATE quarantine_entries SET purged = 1 WHERE id = ?", (eid,))
            conn.commit()
            entry.purged = True
            result.entries.append(entry)
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
    return result


def eligible_for_purge(config: dict[str, Any]) -> list[QuarantineEntry]:
    retention_days = config.get("retention_days", 30)
    cutoff = datetime.now(UTC).timestamp() - retention_days * 86400
    eligible = []
    for entry in list_entries(config):
        ts = datetime.fromisoformat(entry.timestamp).timestamp()
        if ts <= cutoff:
            eligible.append(entry)
    return eligible


def overall_summary(config: dict[str, Any]) -> tuple[int, int]:
    """(item_count, total_bytes) currently sitting in quarantine."""
    entries = list_entries(config)
    return len(entries), sum(e.size_bytes for e in entries)
