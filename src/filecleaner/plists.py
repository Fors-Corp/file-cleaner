"""Read a property list that nothing vouches for: an app's ``Info.plist``, a
device backup's — written by other software, and sometimes damaged."""

from __future__ import annotations

import plistlib
from pathlib import Path
from typing import Any


def load_dict(path: Path) -> dict[str, Any]:
    """The dictionary in the plist at ``path``, or an empty one when there is
    none to be had: the file is missing, unreadable, damaged, or holds
    something that is not a dictionary.

    Deliberately catches everything. ``plistlib`` reports a damaged *binary*
    plist as ``InvalidFileException``, but its XML parser lets through whatever
    went wrong inside it — ``ExpatError`` for a truncated file, ``ValueError``
    for a bad number, ``AttributeError`` for a bad date, ``IndexError`` for a
    key outside a dictionary — so no narrower net holds. One damaged plist
    must not take down a listing of everything beside it."""
    try:
        with path.open("rb") as f:
            data: Any = plistlib.load(f)
    except Exception:
        return {}
    return data if isinstance(data, dict) else {}
