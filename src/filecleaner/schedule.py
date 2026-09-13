"""macOS launchd integration: run a read-only `scan` on a schedule.

Deliberately scoped to the read-only ``scan`` command only — never
``clean --apply`` or ``purge`` — so unattended automation can never perform
an action that this app otherwise requires an explicit, confirmed step for.
A scheduled run's output goes to a log file under the data directory and,
because it's a normal ``fclean scan --json`` invocation, feeds the same
audit trail (``audit.log_scan``) as a manually-run scan.

Nothing here is installed unless the user explicitly runs
``fclean schedule enable`` — this module only ever touches
``~/Library/LaunchAgents`` (or ``launchctl``) when one of its functions is
called directly.
"""

from __future__ import annotations

import os
import plistlib
import subprocess
import sys
from pathlib import Path
from typing import Any

from filecleaner import config as config_mod

LABEL = "com.marcfors.filecleaner.scan"


class ScheduleError(Exception):
    """A launchd operation (install/uninstall) failed, or bad arguments were given."""


def _launch_agents_dir_from_env() -> Path:
    explicit = os.environ.get("FILECLEANER_LAUNCH_AGENTS_DIR")
    if explicit:
        return Path(explicit).expanduser()
    return Path.home() / "Library" / "LaunchAgents"


LAUNCH_AGENTS_DIR = _launch_agents_dir_from_env()


def plist_path() -> Path:
    return LAUNCH_AGENTS_DIR / f"{LABEL}.plist"


def _log_dir() -> Path:
    d = config_mod.DATA_DIR / "schedule"
    d.mkdir(parents=True, exist_ok=True)
    return d


def build_plist(*, every_hours: int) -> dict[str, Any]:
    logs = _log_dir()
    return {
        "Label": LABEL,
        # `-m filecleaner` rather than the `fclean` script path: robust
        # regardless of how the currently-running `fclean` was invoked,
        # since sys.executable always names this same venv's interpreter.
        "ProgramArguments": [sys.executable, "-m", "filecleaner", "scan", "--json"],
        "StartInterval": every_hours * 3600,
        "StandardOutPath": str(logs / "stdout.log"),
        "StandardErrorPath": str(logs / "stderr.log"),
        "RunAtLoad": False,
    }


def _launchctl(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(["launchctl", *args], capture_output=True, text=True, check=False)


def _gui_target() -> str:
    return f"gui/{os.getuid()}"


def enable(*, every_hours: int) -> Path:
    """Write the LaunchAgent plist and (re)bootstrap it with launchctl.
    Returns the plist path. Only ever schedules the read-only `scan`."""
    if every_hours < 1:
        raise ScheduleError("every_hours must be >= 1")
    LAUNCH_AGENTS_DIR.mkdir(parents=True, exist_ok=True)
    path = plist_path()
    with path.open("wb") as f:
        plistlib.dump(build_plist(every_hours=every_hours), f)
    # Bootout first in case a previous version is already loaded —
    # `bootstrap` errors on an already-loaded label rather than replacing it.
    _launchctl("bootout", _gui_target(), str(path))
    result = _launchctl("bootstrap", _gui_target(), str(path))
    if result.returncode != 0:
        raise ScheduleError(f"launchctl bootstrap failed: {result.stderr.strip()}")
    return path


def disable() -> bool:
    """Unload and remove the LaunchAgent. Returns False if none was installed."""
    path = plist_path()
    if not path.exists():
        return False
    _launchctl("bootout", _gui_target(), str(path))
    path.unlink()
    return True


def status() -> dict[str, Any]:
    path = plist_path()
    installed = path.exists()
    loaded = False
    if installed:
        result = _launchctl("print", f"{_gui_target()}/{LABEL}")
        loaded = result.returncode == 0
    return {"installed": installed, "loaded": loaded, "plist_path": str(path)}
