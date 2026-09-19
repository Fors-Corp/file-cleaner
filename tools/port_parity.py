"""Parity checks for the Rust port (docs/PORT.md): the Python implementation
is the reference, and a phase is done when these pass on real data.

    PYTHONPATH=src python tools/port_parity.py protected [--cap N]
    PYTHONPATH=src python tools/port_parity.py scan [ROOT]
    PYTHONPATH=src python tools/port_parity.py scan-json [ROOT]
    PYTHONPATH=src python tools/port_parity.py config-json
    PYTHONPATH=src python tools/port_parity.py pyjson [N]
    PYTHONPATH=src python tools/port_parity.py large-files [PATH...]
    PYTHONPATH=src python tools/port_parity.py duplicates [PATH...]
    PYTHONPATH=src python tools/port_parity.py leftovers
    PYTHONPATH=src python tools/port_parity.py backups
    PYTHONPATH=src python tools/port_parity.py audit
    PYTHONPATH=src python tools/port_parity.py plan [ROOT]

`protected` compares `safety.is_protected` with the Rust port's over real
paths and adversarial respellings of them. Rust may be stricter, never looser.
`scan` compares `scanner.run_scan` (pure Python walker) with the fully native
`fclean-walk scan` — walk, protection re-check, thresholds and coalescing all
done in Rust — on the same root with the same rules.
`scan-json` and `config-json` (phase 2) compare what `fclean scan --json` and
`fclean config show --json` print with what the port prints having read the
same config file itself: byte for byte, but for the scan's wall-clock
`duration_seconds`. `pyjson` checks the port's JSON writer against
`json.dumps` on random floats and strings.
`large-files` and `duplicates` (phase 3) compare what those commands print
with `--json` — for `duplicates`, without `--apply` — with what the port
prints, byte for byte, SHA-256 digests included. PATHS default to home.
`leftovers`, `backups` and `audit` do the same for `fclean leftovers --json`
(each `--kind`), `fclean backups list --json` and `fclean audit --json`.
`plan` has each implementation save a plan of the same scan — the two files
must be the same bytes — and then has each revalidate both files.

Read-only: nothing here moves, restores or purges anything. Exit status 1 on
any disagreement that is not explained.
"""

from __future__ import annotations

import contextlib
import difflib
import json
import os
import random
import re
import struct
import subprocess
import sys
import tempfile
import time
import types
import unicodedata
import warnings
from collections.abc import Callable, Iterator, Sequence
from pathlib import Path
from typing import Any

from filecleaner import (
    audit,
    backups,
    duplicates,
    largefiles,
    leftovers,
    native_walk,
    output,
    plan,
    safety,
    scanner,
)
from filecleaner import config as config_mod
from filecleaner import rules as rules_mod

REPO = Path(__file__).resolve().parent.parent


def helper() -> Path:
    built = REPO / "native" / "fclean-walk" / "target" / "release" / "fclean-walk"
    found = native_walk.helper_path() or (built if built.is_file() else None)
    if found is None:
        sys.exit("fclean-walk is not built: cargo build --release --manifest-path native/fclean-walk/Cargo.toml")
    return found


def environment() -> dict[str, Any]:
    return {
        "home": str(Path.home()),
        "volumes_dir": str(safety._VOLUMES_DIR),
        "self_dirs": [str(p) for p in safety._self_protected_paths()],
    }


# ------------------------------------------------------------------ protected


def rust_protected(paths: list[str], extra_protected: tuple[Path, ...] = ()) -> list[bool]:
    extra = [str(p) for p in extra_protected]
    request = {**environment(), "queries": [{"path": p, "extra_protected": extra} for p in paths]}
    out = subprocess.run([str(helper()), "protected"], input=json.dumps(request), capture_output=True, text=True)
    if out.returncode != 0:
        sys.exit(f"fclean-walk protected failed: {out.stderr.strip()}")
    verdicts: list[bool] = json.loads(out.stdout)
    return verdicts


def _corpus(cap: int) -> list[str]:
    home = Path.home()
    roots = [home / "Library", home, Path("/usr"), Path("/System/Library"), Path("/Library"), Path("/private"),
             Path("/Applications"), Path("/Volumes"), Path("/")]
    seen: set[str] = set()
    for root in roots:
        taken = 0
        for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
            for name in dirnames + filenames:
                path = os.path.join(dirpath, name)
                if path not in seen:
                    seen.add(path)
                    taken += 1
            if taken >= cap:
                break
    real = sorted(seen)
    respelled: list[str] = []
    for path in real[:: max(1, len(real) // 4000)]:
        parent, name = os.path.split(path)
        respelled += [path.lower(), path.upper(), path.swapcase(), unicodedata.normalize("NFD", path),
                      f"{parent}/{name}/../{name}", f"{path.upper()}/does-not-exist/child"]
    return real + [p for p in respelled if p not in seen]


def check_protected(cap: int) -> bool:
    paths = _corpus(cap)
    t0 = time.monotonic()
    rust = rust_protected(paths)
    t_rust = time.monotonic() - t0
    t0 = time.monotonic()
    python = [safety.is_protected(Path(p)) for p in paths]
    t_python = time.monotonic() - t0
    looser = [p for p, py, rs in zip(paths, python, rust, strict=True) if py and not rs]
    stricter = [p for p, py, rs in zip(paths, python, rust, strict=True) if rs and not py]
    print(f"{len(paths):,} paths | protected: python {sum(python):,}, rust {sum(rust):,} | "
          f"python {t_python:.1f}s, rust {t_rust:.1f}s")
    print(f"LOOSER   (python protects, rust does not): {len(looser)}   <-- must be 0")
    for path in looser[:20]:
        print("   ", path)
    print(f"STRICTER (rust protects, python does not): {len(stricter)}   <-- each must be explained")
    for path in stricter[:20]:
        print("   ", path)
    return not looser and not stricter


# ----------------------------------------------------------------------- scan


def scan_request(config: dict[str, Any], root: Path | None, *, now: float, **select: Any) -> dict[str, Any]:
    """Everything the native `scan` needs, taken from the Python side: until
    phase 2, rules and configuration are still Python's to read."""
    selected = scanner.select_rules(config, **select)
    effective_root, _roots, root_in_roots, volume_roots, extra_protected = scanner._scan_setup(config, root=root)
    walks = [
        {"base": str(base), "pattern": pattern, "kind": rule.kind, "excludes": list(rule.exclude_globs),
         "rule_id": rule.id, "min_age_days": rule.min_age_days, "min_size_bytes": rule.min_size_bytes}
        for rule, base in scanner._iter_targets(selected, effective_root, root_in_roots, volume_roots)
        for pattern in rule.include_globs
    ]
    return {**environment(), "extra_protected": [str(p) for p in extra_protected],
            "never_descend": sorted(scanner._NEVER_DESCEND), "now": now, "walks": walks}


def rust_scan(config: dict[str, Any], root: Path | None, **select: Any) -> dict[str, Any]:
    request = scan_request(config, root, now=time.time(), **select)
    out = subprocess.run([str(helper()), "scan"], input=json.dumps(request), capture_output=True, text=True)
    if out.returncode != 0:
        sys.exit(f"fclean-walk scan failed: {out.stderr.strip()}")
    result: dict[str, Any] = json.loads(out.stdout)
    return result


def python_scan(config: dict[str, Any], root: Path | None, **select: Any) -> scanner.ScanResult:
    previous = os.environ.get(native_walk.HELPER_ENV)
    os.environ[native_walk.HELPER_ENV] = "0"  # the reference is the pure-Python walker
    try:
        return scanner.run_scan(config, root=root, **select)
    finally:
        if previous is None:
            del os.environ[native_walk.HELPER_ENV]
        else:
            os.environ[native_walk.HELPER_ENV] = previous


def summarise_rust(result: dict[str, Any]) -> tuple[list[tuple[str, bool, int, str]], list[str]]:
    candidates = [(c["path"], c["is_dir"], c["size"], c["rule_id"]) for c in result["candidates"]]
    errors = [
        f"{e['rule_id']}: cannot read {e['path']}: {os.strerror(e['errno']) if e['errno'] else 'unknown error'}"
        for e in result["errors"]
    ]
    return sorted(candidates), sorted(errors)


def summarise_python(result: scanner.ScanResult) -> tuple[list[tuple[str, bool, int, str]], list[str]]:
    candidates = [(str(c.path), c.is_dir, c.size_bytes, c.rule_id) for c in result.candidates]
    return sorted(candidates), sorted(result.errors)


def check_scan(root: Path | None) -> bool:
    config = config_mod.load_config(warnings=[])
    t0 = time.monotonic()
    rust_candidates, rust_errors = summarise_rust(rust_scan(config, root))
    t_rust = time.monotonic() - t0
    t0 = time.monotonic()
    py_candidates, py_errors = summarise_python(python_scan(config, root))
    t_python = time.monotonic() - t0
    print(f"candidates: python {len(py_candidates)}, rust {len(rust_candidates)} | "
          f"errors: python {len(py_errors)}, rust {len(rust_errors)} | python {t_python:.1f}s, rust {t_rust:.1f}s")
    py_by_path = {c[0]: c for c in py_candidates}
    rust_by_path = {c[0]: c for c in rust_candidates}
    only_python = sorted(set(py_by_path) - set(rust_by_path))
    only_rust = sorted(set(rust_by_path) - set(py_by_path))
    differ = sorted(p for p in set(py_by_path) & set(rust_by_path) if py_by_path[p] != rust_by_path[p])
    for label, paths in (("only python", only_python), ("only rust", only_rust)):
        print(f"{label}: {len(paths)}")
        for path in paths[:10]:
            print("   ", path)
    print(f"same path, different kind/size/rule: {len(differ)}   (a live tree changes between two runs; "
          f"sizes of active caches are expected here, kind or rule are not)")
    for path in differ[:10]:
        print("   ", py_by_path[path], "vs", rust_by_path[path])
    structural = [p for p in differ if py_by_path[p][1] != rust_by_path[p][1] or py_by_path[p][3] != rust_by_path[p][3]]
    # Python stops recording at _MAX_ERRORS; past that only "rust saw at least
    # what python kept" can be asked.
    capped = len(py_errors) >= scanner._MAX_ERRORS
    errors_agree = set(py_errors) <= set(rust_errors) if capped else py_errors == rust_errors
    if not errors_agree:
        for line in sorted(set(py_errors) ^ set(rust_errors))[:10]:
            print("    error on one side only:", line)
    return not only_python and not only_rust and not structural and errors_agree


# ------------------------------------------------------------ scan-json, config-json

_DURATION = re.compile(r'"duration_seconds": [-+0-9.e]+')


def native_request(**request: Any) -> dict[str, Any]:
    """Where the port should look, so that it reads what this process reads.
    It finds all of these for itself when run on its own; here they are
    stated because tests move them (and "self" means the Python package)."""
    return {**environment(), "config_dir": str(config_mod.CONFIG_DIR), "data_dir": str(config_mod.DATA_DIR), **request}


def rust(command: str, request: dict[str, Any]) -> subprocess.CompletedProcess[str]:
    return subprocess.run([str(helper()), command], input=json.dumps(request), capture_output=True, text=True)


def scan_selection(root: Path | None, *, now: float, only_rules: set[str] | None = None,
                   include_disabled: bool = False, extra_excludes: tuple[Path, ...] = ()) -> dict[str, Any]:
    """`fclean scan [ROOT] --rules ... --include-disabled --exclude ...`, as the port is asked for it."""
    return {
        "root": None if root is None else str(root), "now": now, "include_disabled": include_disabled,
        "only_rules": None if only_rules is None else sorted(only_rules), "extra_excludes": [str(p) for p in extra_excludes],
    }


def rust_scan_json(root: Path | None, *, now: float, **select: Any) -> str:
    out = rust("scan-json", native_request(**scan_selection(root, now=now, **select)))
    if out.returncode != 0:
        raise RuntimeError(out.stderr.strip())
    return out.stdout


def python_scan_json(root: Path | None, *, now: float, **select: Any) -> str:
    """What `fclean scan --json` prints — without its entry in the audit log."""
    return output.dumps(python_scan_result(root, now=now, **select)) + "\n"


def python_scan_result(root: Path | None, *, now: float, **select: Any) -> scanner.ScanResult:
    """The scan behind `fclean scan` and `fclean clean`.
    Through the native walker, whose results come in a defined order (the
    pure-Python walk yields in whatever order the filesystem lists), and with
    the clock held still so that both sides agree on every age."""
    config = config_mod.load_config(warnings=[])
    previous, clock = os.environ.get(native_walk.HELPER_ENV), scanner.time
    os.environ[native_walk.HELPER_ENV] = str(helper())
    scanner.time = types.SimpleNamespace(time=lambda: now, monotonic=time.monotonic)  # type: ignore[assignment]
    try:
        result = scanner.run_scan(config, root=root, **select)
    finally:
        scanner.time = clock
        if previous is None:
            del os.environ[native_walk.HELPER_ENV]
        else:
            os.environ[native_walk.HELPER_ENV] = previous
    return result


def python_config_json() -> str:
    config = config_mod.load_config(warnings=[])
    listed = [{**rule.to_dict(), "enabled": config_mod.is_rule_enabled(config, rule.id, rule.enabled_by_default)}
              for rule in rules_mod.all_rules(config)]
    return output.dumps({"config_file": str(config_mod.CONFIG_FILE), "config": config, "rules": listed}) + "\n"


def rust_config_json() -> str:
    out = rust("config-json", native_request())
    if out.returncode != 0:
        raise RuntimeError(out.stderr.strip())
    return out.stdout


def without_duration(report: str) -> str:
    return _DURATION.sub('"duration_seconds": 0.0', report)


def _same(label: str, python: str, native: str) -> bool:
    if python == native:
        print(f"{label}: identical, {len(python.encode()):,} bytes")
        return True
    diff = list(difflib.unified_diff(python.splitlines(), native.splitlines(), "python", "rust", lineterm="", n=1))
    print(f"{label}: DIFFERENT ({len(diff)} diff lines)")
    print("\n".join(diff[:40]))
    return False


def check_scan_json(root: Path | None) -> bool:
    now = time.time()
    ok = True
    for label, select in (("scan --json", {}), ("scan --json --include-disabled", {"include_disabled": True})):
        t0 = time.monotonic()
        native = rust_scan_json(root, now=now, **select)
        t_rust = time.monotonic() - t0
        t0 = time.monotonic()
        python = python_scan_json(root, now=now, **select)
        print(f"  python {time.monotonic() - t0:.1f}s, rust {t_rust:.1f}s")
        ok = _same(label, without_duration(python), without_duration(native)) and ok
    return ok


def check_config_json() -> bool:
    return _same("config show --json", python_config_json(), rust_config_json())


def pyjson_corpus(count: int, seed: int = 20260919) -> tuple[list[str], list[float]]:
    rng = random.Random(seed)
    floats = [0.0, -0.0, 1.0, 1e15, 1e16, 9999999999999998.0, 1e-4, 1e-5, 0.1 + 0.2, 5e-324, 1.7976931348623157e308,
              1789775128.5018933, float("inf"), float("-inf"), float("nan")]
    while len(floats) < count:
        bits = rng.getrandbits(64)
        floats.append(struct.unpack("<d", struct.pack("<Q", bits))[0])
        floats.append(rng.uniform(0, 2e9))  # what a modification time looks like
        floats.append(round(rng.uniform(0, 500), 3))  # and a duration
    alphabet = ['"', "\\", "/", "\n", "\r", "\t", "\b", "\f", "\x00", "\x1f", "\x7f", "é", "\u2028", "\u2029", "𝄞", "a", " ", "'"]
    strings = ["", "plain"] + ["".join(rng.choice(alphabet) for _ in range(rng.randint(1, 12))) for _ in range(count)]
    return strings, floats[:count]


def check_pyjson(count: int) -> bool:
    strings, floats = pyjson_corpus(count)
    out = rust("pyjson", {"strings": strings, "float_bits": [struct.unpack("<Q", struct.pack("<d", f))[0] for f in floats]})
    if out.returncode != 0:
        raise RuntimeError(out.stderr.strip())
    return _same(f"json writer, {len(strings):,} strings and {len(floats):,} floats",
                 output.dumps({"strings": strings, "floats": floats}) + "\n", out.stdout)


# ------------------------------------------- phase 3: the read-only commands


@contextlib.contextmanager
def through_the_native_walker() -> Iterator[None]:
    """The reference for anything built on ``filewalk`` is Python *over the
    native walk*: which of a hard-linked file's names is reported is the
    walker's to choose, so the pure-Python walk gives a different and equally
    valid answer. A silent fallback to it would compare the wrong thing, and
    is an error here."""
    previous = os.environ.get(native_walk.HELPER_ENV)
    os.environ[native_walk.HELPER_ENV] = str(helper())
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("error", RuntimeWarning)
            yield
    finally:
        if previous is None:
            del os.environ[native_walk.HELPER_ENV]
        else:
            os.environ[native_walk.HELPER_ENV] = previous


def command_roots(paths: Sequence[str]) -> list[Path]:
    """What ``fclean duplicates`` and ``fclean large-files`` make of PATHS."""
    return [Path(p).expanduser() for p in paths] if paths else [Path.home()]


def rust_json(command: str, **request: Any) -> str:
    out = rust(command, native_request(**request))
    if out.returncode != 0:
        raise RuntimeError(out.stderr.strip())
    return out.stdout


def python_large_files_json(paths: Sequence[str] = (), *, top: int = 30, min_size: int = 0) -> str:
    config = config_mod.load_config(warnings=[])
    with through_the_native_walker():
        found = largefiles.find_large_files(command_roots(paths), config, top=top, min_size_bytes=min_size)
    return output.dumps({"files": [f.to_dict() for f in found]}) + "\n"


def rust_large_files_json(paths: Sequence[str] = (), **options: int) -> str:
    return rust_json("large-files-json", paths=list(paths), **options)


def python_duplicates_json(paths: Sequence[str] = (), *, top: int = 30, min_size: int = 4096) -> str:
    """What ``fclean duplicates --json`` prints when it is not asked to apply."""
    config = config_mod.load_config(warnings=[])
    with through_the_native_walker():
        groups = duplicates.find_duplicates(command_roots(paths), config, min_size_bytes=min_size, max_groups=top)
    report = {"groups": [g.to_dict() for g in groups], "total_wasted_bytes": sum(g.wasted_bytes for g in groups)}
    return output.dumps(report) + "\n"


def rust_duplicates_json(paths: Sequence[str] = (), **options: int) -> str:
    return rust_json("duplicates-json", paths=list(paths), **options)


def python_leftovers_json(kind: str = "all", *, now: float) -> str:
    """What ``fclean leftovers --kind KIND --json`` prints when it is not asked
    to apply, with the clock held still so both sides agree on every age."""
    config = config_mod.load_config(warnings=[])
    clock = leftovers.time
    leftovers.time = types.SimpleNamespace(time=lambda: now)  # type: ignore[assignment]
    try:
        with through_the_native_walker():
            candidates = leftovers.find_app_leftovers(config) if kind in ("apps", "all") else []
            candidates += leftovers.find_installer_cleanup(config) if kind in ("installers", "all") else []
    finally:
        leftovers.time = clock
    report = {"candidates": [c.to_dict() for c in candidates], "total_size_bytes": sum(c.size_bytes for c in candidates)}
    return output.dumps(report) + "\n"


def rust_leftovers_json(kind: str = "all", *, now: float) -> str:
    # Python looks the applications folders up once, on import; tests move them.
    apps = [str(path) for path in leftovers._APPLICATIONS_DIRS]
    return rust_json("leftovers-json", kind=kind, now=now, applications_dirs=apps)


def check_leftovers_json() -> bool:
    now = time.time()
    ok = True
    for kind in ("apps", "installers", "all"):
        t0 = time.monotonic()
        native = rust_leftovers_json(kind, now=now)
        t_rust = time.monotonic() - t0
        t0 = time.monotonic()
        python = python_leftovers_json(kind, now=now)
        print(f"  python {time.monotonic() - t0:.1f}s, rust {t_rust:.1f}s")
        ok = _same(f"leftovers --kind {kind} --json", python, native) and ok
    return ok


def python_backups_json(base: Path | None = None) -> str:
    return output.dumps({"backups": [b.to_dict() for b in backups.find_backups(base)]}) + "\n"


def rust_backups_json(base: Path | None = None) -> str:
    return rust_json("backups-list-json", base=None if base is None else str(base))


def check_backups_json() -> bool:
    try:
        python = python_backups_json()
    except backups.BackupAccessDenied as denied:
        # Nothing to compare without Full Disk Access; the port must say so too.
        refused = rust("backups-list-json", native_request())
        print(f"backups list --json: macOS refused both (rust exit {refused.returncode})")
        return refused.returncode != 0 and str(denied) in refused.stderr
    return _same("backups list --json", python, rust_backups_json())


def python_audit_json(limit: int = 50, action: str | None = None) -> str:
    """What ``fclean audit --json`` prints. Python's reader creates the log
    and sets its mode on the way in; a parity check is no reason to touch the
    data directory, so the reader is pointed at the file as it is."""
    real = audit.get_audit_log_path
    audit.get_audit_log_path = lambda: config_mod.AUDIT_LOG_PATH  # type: ignore[assignment]
    try:
        entries = audit.read_audit_log(limit=limit, action=action)
    finally:
        audit.get_audit_log_path = real  # type: ignore[assignment]
    return output.dumps({"entries": entries}) + "\n"


def rust_audit_json(limit: int = 50, action: str | None = None) -> str:
    return rust_json("audit-json", limit=limit, action=action)


def check_audit_json() -> bool:
    ok = True
    for limit, action in ((50, None), (0, None), (7, "scan"), (0, "purge")):
        label = f"audit --limit {limit}" + (f" --action {action}" if action else "") + " --json"
        ok = _same(label, python_audit_json(limit, action), rust_audit_json(limit, action)) and ok
    return ok


def python_save_plan(path: Path, root: Path | None, *, now: float, created_at: str, **select: Any) -> None:
    """``fclean clean --save-plan PATH``, with the plan's own clock held still."""
    saved = plan.CleanupPlan.from_scan(python_scan_result(root, now=now, **select))
    saved.created_at = created_at
    plan.save_plan(saved, path)


def rust_save_plan(path: Path, root: Path | None, *, now: float, created_at: str, **select: Any) -> None:
    rust_json("plan-save", save_plan=str(path), created_at=created_at, **scan_selection(root, now=now, **select))


def python_plan_check_json(path: Path) -> str:
    """What ``fclean apply PLAN`` would move and what it would leave, and why."""
    fresh, stale = plan.revalidate(plan.load_plan(path))
    return output.dumps({"fresh": [c.to_dict() for c in fresh], "stale": [s.to_dict() for s in stale]}) + "\n"


def rust_plan_check_json(path: Path) -> str:
    return rust_json("plan-check-json", plan=str(path))


def check_plan(root: Path | None) -> bool:
    """Each writes a plan of the same scan; the two files must be the same
    bytes, and each reader must say the same of either."""
    now = time.time()
    created_at = "2026-09-19T00:00:00+00:00"
    with tempfile.TemporaryDirectory() as scratch:
        by_python, by_rust = Path(scratch) / "python.json", Path(scratch) / "rust.json"
        python_save_plan(by_python, root, now=now, created_at=created_at)
        rust_save_plan(by_rust, root, now=now, created_at=created_at)
        ok = _same("plan file", by_python.read_text(encoding="utf-8"), by_rust.read_text(encoding="utf-8"))
        for written, path in (("python's", by_python), ("rust's", by_rust)):
            ok = _same(f"revalidating {written} plan", python_plan_check_json(path), rust_plan_check_json(path)) and ok
    return ok


_READ_ONLY: dict[str, tuple[Callable[..., str], Callable[..., str]]] = {
    "large-files": (python_large_files_json, rust_large_files_json),
    "duplicates": (python_duplicates_json, rust_duplicates_json),
}


def check_read_only(command: str, paths: Sequence[str]) -> bool:
    python_json, native_json = _READ_ONLY[command]
    t0 = time.monotonic()
    native = native_json(paths)
    t_rust = time.monotonic() - t0
    t0 = time.monotonic()
    python = python_json(paths)
    print(f"  python {time.monotonic() - t0:.1f}s, rust {t_rust:.1f}s")
    return _same(f"{command} --json", python, native)


if __name__ == "__main__":
    args = sys.argv[1:]
    if args[:1] == ["protected"]:
        cap = int(args[args.index("--cap") + 1]) if "--cap" in args else 30000
        ok = check_protected(cap)
    elif args[:1] == ["scan"]:
        ok = check_scan(Path(args[1]).expanduser() if len(args) > 1 else None)
    elif args[:1] == ["scan-json"]:
        ok = check_scan_json(Path(args[1]).expanduser() if len(args) > 1 else None)
    elif args[:1] == ["config-json"]:
        ok = check_config_json()
    elif args[:1] == ["pyjson"]:
        ok = check_pyjson(int(args[1]) if len(args) > 1 else 20000)
    elif args[:1] == ["leftovers"]:
        ok = check_leftovers_json()
    elif args[:1] == ["backups"]:
        ok = check_backups_json()
    elif args[:1] == ["audit"]:
        ok = check_audit_json()
    elif args[:1] == ["plan"]:
        ok = check_plan(Path(args[1]).expanduser() if len(args) > 1 else None)
    elif args[:1] and args[0] in _READ_ONLY:
        ok = check_read_only(args[0], args[1:])
    else:
        sys.exit(__doc__)
    print("PARITY" if ok else "MISMATCH")
    sys.exit(0 if ok else 1)
