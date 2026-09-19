"""Time one read-only scan. Usage: bench_scan.py <label> <root>

Calls scanner.run_scan — the function `fclean scan` calls — with the real
config, but skips the CLI wrapper so nothing is appended to the audit log.
Read-only: a scan never moves, restores or purges anything.
"""

from __future__ import annotations

import hashlib
import json
import resource
import sys
import time
from pathlib import Path

from filecleaner import config as config_mod
from filecleaner import safety, scanner

label, root = sys.argv[1], Path(sys.argv[2]).expanduser()
cfg = config_mod.load_config(warnings=[])

# Count the work done, so "faster" can be told apart from "did less".
# list.append is atomic under the GIL; the walks run on several threads.
_listed: list[int] = []
_orig_iter_dir = scanner._iter_dir


def _counting_iter_dir(path):  # type: ignore[no-untyped-def]
    entries = list(_orig_iter_dir(path))
    _listed.append(len(entries))
    return iter(entries)


scanner._iter_dir = _counting_iter_dir

r0 = resource.getrusage(resource.RUSAGE_SELF)
t0 = time.monotonic()
result = scanner.run_scan(cfg, root=root)
wall = time.monotonic() - t0
r1 = resource.getrusage(resource.RUSAGE_SELF)

paths = sorted(str(c.path) for c in result.candidates)
print(json.dumps({
    "label": label,
    "code": safety.__file__,
    "root": str(root),
    "wall_s": round(wall, 1),
    "user_s": round(r1.ru_utime - r0.ru_utime, 1),
    "sys_s": round(r1.ru_stime - r0.ru_stime, 1),
    "cpu_s": round((r1.ru_utime - r0.ru_utime) + (r1.ru_stime - r0.ru_stime), 1),
    "dirs_listed": len(_listed),
    "entries_seen": sum(_listed),
    "candidates": len(paths),
    "errors": len(result.errors),
    "fingerprint": hashlib.sha256("\n".join(paths).encode()).hexdigest()[:16],
}))
