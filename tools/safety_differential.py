"""Differential test: a reference ``safety.is_protected`` vs the current one,
over a large corpus of real paths, adversarial respellings of them, and
``tests/safety_cases.json``.

The deny-list may only ever get STRICTER. This proves it for a change:
  * LOOSER (reference protected, current does not) must be 0;
  * an independent oracle — inode identity with an existing deny directory,
    which shares no code with either implementation — must never find a
    path physically inside a deny dir that the current check lets through;
  * every STRICTER verdict is attributed to the deny entry it respells.

The reference defaults to ``tools/safety_1_3_0.py``, the module as it
shipped in 1.3.0 (before the case/normalisation fix). To vet a future
change, save the current ``safety.py`` somewhere first and pass it:

    PYTHONPATH=src python tools/safety_differential.py [reference_safety.py]

Read-only: lists directory names and lstat()s. Never opens, moves or
deletes anything. Run from the repository root. Takes a few minutes; set
CAP=5000 for a quick pass.
"""

from __future__ import annotations

import importlib.util
import json
import os
import sys
import tempfile
import time
import unicodedata
from collections import Counter
from pathlib import Path

HERE = Path(__file__).parent
REFERENCE = Path(sys.argv[1]) if len(sys.argv) > 1 else HERE / "safety_1_3_0.py"
spec = importlib.util.spec_from_file_location("safety_old", REFERENCE)
assert spec and spec.loader
old = importlib.util.module_from_spec(spec)
spec.loader.exec_module(old)

from filecleaner import safety as new  # noqa: E402

print(f"reference: {REFERENCE}\ncurrent:   {new.__file__}", flush=True)
# The reference is loaded from somewhere else, so its idea of "my own code"
# would differ from the current module's by construction, not by behaviour.
old._self_protected_paths = lambda: [Path(new.__file__).resolve().parent]

REAL_HOME = Path.home()
CAP_PER_ROOT = int(os.environ.get("CAP", "60000"))
ROOTS = [
    REAL_HOME / "Library" / "Application Support",
    REAL_HOME / "Library",
    REAL_HOME,
    Path("/usr"),
    Path("/System/Library"),
    Path("/Library"),
    Path("/private"),
    Path("/Applications"),
    Path("/opt"),
    Path("/Volumes"),
    Path("/"),
]


def gather() -> list[str]:
    seen: set[str] = set()
    for root in ROOTS:
        taken = 0
        for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
            for name in dirnames + filenames:
                p = os.path.join(dirpath, name)
                if p not in seen:
                    seen.add(p)
                    taken += 1
            if taken >= CAP_PER_ROOT:
                break
        print(f"  {root}: {taken} paths", flush=True)
    return sorted(seen)


def variants(path: str) -> list[str]:
    """Adversarial respellings of a real path."""
    parent, name = os.path.split(path)
    out = [path.lower(), path.upper(), path.swapcase(), unicodedata.normalize("NFD", path)]
    out.append(unicodedata.normalize("NFC", path))
    out.append(f"{parent}/./{name}")
    out.append(f"{parent}/{name}/../{name}")
    out.append(f"{path}/does-not-exist/child")
    out.append(f"{path.upper()}/does-not-exist/child")
    return [v for v in out if v != path]


# ---- independent oracle: inode identity with an existing deny directory ----
_stat_cache: dict[str, tuple[int, int] | None] = {}


def _ident(p: str) -> tuple[int, int] | None:
    if p not in _stat_cache:
        try:
            st = os.stat(p)  # follows symlinks, like resolve()
            _stat_cache[p] = (st.st_dev, st.st_ino)
        except OSError:
            _stat_cache[p] = None
    return _stat_cache[p]


DENY_DIRS: list[str] = []  # the deny directories exactly as the OLD check spells them
HOME_DIR = ""


def deny_idents(home: Path, volume_roots: list[Path], extra: tuple[Path, ...]) -> tuple[set[tuple[int, int]], tuple[int, int] | None]:
    global DENY_DIRS, HOME_DIR
    dirs = [Path(d) for d in new.ABSOLUTE_DENY_PATHS]
    for root in volume_roots:
        dirs += [root / sub for sub in new.RELATIVE_DENY_SUBPATHS]
    dirs += [home / sub for sub in new.HOME_DENY_SUBPATHS]
    dirs += [Path(new.__file__).resolve().parent]
    dirs += [e.resolve() for e in extra]
    DENY_DIRS = [str(d) for d in dirs]
    HOME_DIR = str(home)
    idents = {i for d in dirs if (i := _ident(str(d))) is not None}
    return idents, _ident(str(home))


def oracle(path: str, idents: set[tuple[int, int]], home_ident: tuple[int, int] | None) -> bool | None:
    """True if the path is physically at/below an existing deny directory.
    None when the path itself does not exist (no inode to compare)."""
    real = os.path.realpath(path)
    me = _ident(real)
    if me is None:
        return None
    if me == home_ident:
        return True
    cur = real
    while True:
        i = _ident(cur)
        if i is not None and i in idents:
            return True
        parent = os.path.dirname(cur)
        if parent == cur:
            return False
        cur = parent


def classify(path: str) -> str:
    """Why is the new check stricter on this path?"""
    # The old check said "not under any deny dir" comparing exact strings. If the
    # resolved path IS under one once both sides are case-folded + normalised,
    # then the spelling is the whole difference, and we can name the entry.
    resolved = str(Path(path).resolve(strict=False))
    key = new._key(resolved)
    if key == new._key(HOME_DIR):
        return "respelling of: <home itself>"
    for d in DENY_DIRS:
        dk = new._key(d)
        if key == dk or key.startswith(dk.rstrip("/") + "/"):
            shown = d.replace(HOME_DIR, "~") if HOME_DIR and d.startswith(HOME_DIR) else d
            return f"respelling of: {shown}"
    return "OTHER (needs a manual explanation)"


report: list[str] = []
looser: list[str] = []
stricter: Counter[str] = Counter()
stricter_examples: dict[str, list[str]] = {}
oracle_violations: list[str] = []


def compare(paths: list[str], label: str, idents: set[tuple[int, int]], home_ident: tuple[int, int] | None,
            extra: tuple[Path, ...] = ()) -> None:
    t_old = t_new = 0.0
    n_prot = n_oracle = 0
    for p in paths:
        path = Path(p)
        a = time.process_time()
        o = old.is_protected(path, extra_protected=extra)
        b = time.process_time()
        n = new.is_protected(path, extra_protected=extra)
        c = time.process_time()
        t_old += b - a
        t_new += c - b
        n_prot += n
        if o and not n:
            looser.append(f"{label}\t{p}")
        elif n and not o:
            why = classify(p)
            stricter[why] += 1
            stricter_examples.setdefault(why, [])
            if len(stricter_examples[why]) < 3:
                stricter_examples[why].append(p)
        truth = oracle(p, idents, home_ident)
        if truth:
            n_oracle += 1
            if not n:
                oracle_violations.append(f"{label}\t{p}")
    line = (f"{label}: {len(paths)} paths | new protects {n_prot} | inode-oracle says inside a deny dir: {n_oracle} | "
            f"CPU old {t_old:.1f}s ({t_old / max(len(paths), 1) * 1e6:.0f} us/call) new {t_new:.1f}s "
            f"({t_new / max(len(paths), 1) * 1e6:.0f} us/call)")
    print(line, flush=True)
    report.append(line)


# ------------------------------ phase 1: real paths ------------------------------
print("gathering real paths ...", flush=True)
corpus = gather()
print(f"corpus: {len(corpus)} real paths", flush=True)
idents, home_ident = deny_idents(REAL_HOME.resolve(), [r.resolve() for r in new._volume_roots()], ())
compare(corpus, "real paths", idents, home_ident)

step = max(1, len(corpus) // 6000)
sample = corpus[::step]
adversarial = [v for p in sample for v in variants(p)]
compare(adversarial, "adversarial respellings of real paths", idents, home_ident)

# ------------------------------ phase 2: the table ------------------------------
table = json.loads(Path("tests/safety_cases.json").read_text())
tmp = Path(tempfile.mkdtemp(prefix="fc-diff-")).resolve()
home = tmp / "hôme-é"
volumes = tmp / "Volumes"
self_dir = Path(new.__file__).resolve().parent
ph = {
    "{TMP}": str(tmp), "{HOME}": str(home),
    "{HOME_NFD}": str(home.parent / unicodedata.normalize("NFD", home.name)),
    "{HOME_SWAPCASE}": str(home.parent / home.name.swapcase()),
    "{VOLUMES}": str(volumes), "{SELF}": str(self_dir),
    "{SELF_SWAPCASE}": str(self_dir.parent / self_dir.name.swapcase()),
}


def expand(s: str) -> str:
    for k, v in ph.items():
        s = s.replace(k, v)
    return s


for d in table["setup"]["dirs"]:
    Path(expand(d)).mkdir(parents=True, exist_ok=True)
for link in table["setup"]["symlinks"]:
    lp = Path(expand(link["link"]))
    lp.parent.mkdir(parents=True, exist_ok=True)
    lp.symlink_to(expand(link["target"]))

Path.home = staticmethod(lambda: home)  # type: ignore[method-assign]
os.environ["HOME"] = str(home)
os.chdir(home)
new._VOLUMES_DIR = volumes
new.reset_caches()
# The old module hard-codes /Volumes; give it the same fake mounts so that
# volume rows compare behaviour, not fixture visibility.
old._volume_roots = lambda: [Path("/")] + [e for e in volumes.iterdir() if e.is_dir() or e.is_symlink()]

# SELF rows: the old module lives in the scratchpad, so its "own code" dir
# differs from the new one's by construction — point it at the same place.
old._self_protected_paths = lambda: [self_dir]

by_extra: dict[tuple[str, ...], list[dict]] = {}
for case in table["cases"]:
    by_extra.setdefault(tuple(case.get("extra_protected", ())), []).append(case)
wrong_expectation: list[str] = []
for extra_raw, cases in by_extra.items():
    extra = tuple(Path(expand(e)) for e in extra_raw)
    _stat_cache.clear()
    idents, home_ident = deny_idents(home, [Path("/")] + [e.resolve() for e in volumes.iterdir()], extra)
    compare([expand(c["path"]) for c in cases], f"table (extra_protected={len(extra)})", idents, home_ident, extra)
    for c in cases:
        if new.is_protected(Path(expand(c["path"])), extra_protected=extra) is not c["protected"]:
            wrong_expectation.append(c["path"])

# ------------------------------------ verdict ------------------------------------
out = ["", "=" * 78, "DIFFERENTIAL VERDICT", "=" * 78, *report, ""]
out.append(f"LOOSER  (old protected, new does not): {len(looser)}   <-- must be 0")
out += [f"   {x}" for x in looser[:50]]
out.append(f"INODE-ORACLE VIOLATIONS (physically inside a deny dir, new says unprotected): {len(oracle_violations)}   <-- must be 0")
out += [f"   {x}" for x in oracle_violations[:50]]
out.append(f"TABLE ROWS WHERE NEW != EXPECTED: {len(wrong_expectation)}   <-- must be 0")
out.append(f"STRICTER (new protects, old did not): {sum(stricter.values())}")
for why, n in stricter.most_common():
    out.append(f"   {n:7d}  {why}")
    for ex in stricter_examples[why]:
        out.append(f"              e.g. {ex.replace(str(REAL_HOME), '~').replace(str(tmp), '{TMP}')}")
print("\n".join(out))
sys.exit(1 if (looser or oracle_violations or wrong_expectation) else 0)
