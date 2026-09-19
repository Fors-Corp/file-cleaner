"""Client for ``fclean-walk``, the optional native scan walker.

A home-directory walk — for ``scan``, and for ``duplicates`` / ``large-files``
(see ``filewalk``) — is bound by directory I/O latency, and the Python
walk cannot spread that across cores under the GIL. ``fclean-walk`` (Rust,
in ``native/fclean-walk``) does the same walk with every core, shares one
traversal between rules that start in the same place, and sizes matched
directories with ``getattrlistbulk(2)`` instead of one ``lstat`` per file.

It is an accelerator, never an authority:

* It is optional. With no helper installed — or if it fails in any way —
  ``scan`` returns ``None`` and the scanner walks in Python, as before.
* It is only ever located next to this package or via an explicit
  environment variable, never through ``PATH``.
* What it reports is treated as untrusted by the scanner, which re-checks
  every path against the deny-list itself before using it.

This module knows the helper's protocol and nothing about rules or
candidates; turning matches into candidates is the scanner's job.
"""

from __future__ import annotations

import json
import math
import os
import subprocess
import warnings
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

# Path to the helper, or "0"/"off" to force the Python walker.
HELPER_ENV = "FCLEAN_NATIVE_WALK"
_BUNDLED_HELPER = Path(__file__).parent / "_bin" / "fclean-walk"
_DISABLED = frozenset({"", "0", "off", "false", "no"})

ProgressHook = Callable[[int, int, str], None]  # (dirs done, walk index, relative path)


@dataclass(frozen=True)
class Walk:
    base: str
    pattern: str
    kind: str
    excludes: tuple[str, ...]


@dataclass(frozen=True)
class Match:
    walk: int
    path: str
    is_dir: bool
    size: int
    mtime: float


@dataclass(frozen=True)
class ReadError:
    walk: int
    path: str
    errno: int


@dataclass
class Outcome:
    matches: list[Match] = field(default_factory=list)
    errors: list[ReadError] = field(default_factory=list)
    dirs: int = 0


@dataclass(frozen=True)
class FoundFile:
    path: str
    root: int  # index into the roots that were asked for
    size: int
    mtime: float


def helper_path() -> Path | None:
    """The helper to use, or None to walk in Python."""
    configured = os.environ.get(HELPER_ENV)
    if configured is None:
        candidate = _BUNDLED_HELPER
    elif configured.strip().lower() in _DISABLED:
        return None
    else:
        candidate = Path(configured)
    return candidate if candidate.is_file() and os.access(candidate, os.X_OK) else None


def _gave_up(reason: str) -> None:
    # Absent is normal and silent; *present but broken* is worth a word,
    # because the scan is about to get several times slower.
    warnings.warn(
        f"native scan helper failed ({reason}); falling back to the Python walker. "
        "If File Cleaner was just updated, re-run ./install.sh to rebuild the helper.",
        RuntimeWarning,
        stacklevel=3,
    )


def _converse(args: list[str], request: dict[str, Any], on_message: Callable[[dict[str, Any]], None]) -> bool:
    """Send one request to the helper and feed every reply to ``on_message``.
    True only if it ran to completion: exit status 0 and a final ``done``.
    Anything else has already been warned about, and the caller must throw
    away whatever it collected — a partial result is never used."""
    helper = helper_path()
    if helper is None:
        return False
    try:
        proc = subprocess.Popen(
            [str(helper), *args],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
        )
    except OSError as exc:
        _gave_up(f"cannot start {helper}: {exc}")
        return False

    finished = False
    try:
        assert proc.stdin is not None and proc.stdout is not None and proc.stderr is not None
        # The helper reads its whole request before writing anything, so
        # this cannot deadlock against its output.
        proc.stdin.write(json.dumps(request))
        proc.stdin.close()
        for line in proc.stdout:
            message = json.loads(line)
            if "done" in message:
                finished = True
            on_message(message)
        returncode = proc.wait()
        complaint = proc.stderr.read().strip()
    except (OSError, ValueError, KeyError, TypeError) as exc:
        _gave_up(f"unreadable output: {exc}")
        return False
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait()
        for stream in (proc.stdin, proc.stdout, proc.stderr):
            if stream is not None:
                stream.close()

    if returncode != 0 or not finished:
        _gave_up(complaint or f"exit status {returncode}")
        return False
    return True


def scan(
    walks: Sequence[Walk],
    *,
    deny_home: str,
    deny_prefixes: Sequence[str],
    never_descend: Sequence[str],
    on_progress: ProgressHook | None = None,
) -> Outcome | None:
    """Run every walk in the helper. None means "not available — walk in
    Python": no helper, or a helper that did not finish cleanly. A partial
    result is never returned."""
    if not walks:
        return None
    outcome = Outcome()

    def on_message(message: dict[str, Any]) -> None:
        if "m" in message:
            outcome.matches.append(
                Match(
                    walk=int(message["m"]),
                    path=str(message["p"]),
                    is_dir=bool(message["d"]),
                    size=int(message["s"]),
                    mtime=float(message["t"]),
                )
            )
        elif "e" in message:
            outcome.errors.append(ReadError(int(message["e"]), str(message["p"]), int(message["errno"])))
        elif "n" in message:
            if on_progress is not None:
                on_progress(int(message["n"]), int(message["w"]), str(message["r"]))
        elif "done" in message:
            outcome.dirs = int(message["done"])

    request = {
        "deny_home": deny_home,
        "deny_prefixes": list(deny_prefixes),
        "never_descend": list(never_descend),
        "walks": [{"base": w.base, "pattern": w.pattern, "kind": w.kind, "excludes": list(w.excludes)} for w in walks],
    }
    if not _converse([], request, on_message):
        return None
    reported = [m.walk for m in outcome.matches] + [e.walk for e in outcome.errors]
    if any(not 0 <= walk < len(walks) for walk in reported):
        _gave_up("it reported a walk that was never requested")
        return None
    return outcome


def files(
    roots: Sequence[str], *, min_size: int, deny_home: str, deny_prefixes: Sequence[str]
) -> list[FoundFile] | None:
    """Every regular file of at least ``min_size`` bytes under ``roots``, once
    per physical file (the helper's port of ``filewalk.walk_unique_files``).
    None means "not available — walk in Python", as for ``scan``."""
    if not roots:
        return None
    found: list[FoundFile] = []

    def on_message(message: dict[str, Any]) -> None:
        if "f" in message:
            found.append(
                FoundFile(str(message["f"]), int(message["r"]), int(message["s"]), float(message["t"]))
            )

    request = {
        "deny_home": deny_home,
        "deny_prefixes": list(deny_prefixes),
        "roots": list(roots),
        "min_size": min_size,
    }
    if not _converse(["files"], request, on_message):
        return None
    if any(not 0 <= item.root < len(roots) for item in found):
        _gave_up("it reported a root that was never requested")
        return None
    return found


def dir_sizes(dirs: Sequence[str]) -> list[tuple[int, float]] | None:
    """``scanner.dir_stats`` for many directories at once: total size and
    newest mtime below each, in the order asked. None means "not available —
    size them in Python", as for ``scan``; an answer that does not cover
    every directory exactly once, with sane numbers, counts as a failure."""
    if not dirs:
        return None
    sized: dict[int, tuple[int, float]] = {}
    repeated = False

    def on_message(message: dict[str, Any]) -> None:
        nonlocal repeated
        if "i" in message:
            index = int(message["i"])
            repeated = repeated or index in sized
            sized[index] = (int(message["s"]), float(message["t"]))

    if not _converse(["sizes"], {"dirs": list(dirs)}, on_message):
        return None
    sane = all(size >= 0 and math.isfinite(mtime) and mtime >= 0 for size, mtime in sized.values())
    if repeated or set(sized) != set(range(len(dirs))) or not sane:
        _gave_up("it did not size exactly the directories it was asked to")
        return None
    return [sized[index] for index in range(len(dirs))]
