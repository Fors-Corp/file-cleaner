"""The Rust port against the Python it is a port of (docs/PORT.md).

Phase 1: ``fclean-walk scan`` does the whole scan natively — walk, protection
re-check, thresholds, coalescing — and must produce exactly what
``scanner.run_scan`` does with the pure-Python walker.

Phase 2: ``scan-json`` and ``config-json`` read the config file, the rules
and the volumes for themselves and must print, byte for byte, what
``fclean scan --json`` and ``fclean config show --json`` print.

Phase 3: the read-only commands — ``large-files``, ``duplicates`` (finding),
``leftovers`` (finding), ``backups list`` and ``audit`` print with ``--json``
what Python prints, byte for byte, SHA-256 digests and modification times
included; and a plan file written by either is the same bytes, and is
accepted — and found stale for the same reasons — by the other.

The comparisons live in ``tools/port_parity.py`` so that the checks run by
hand on a real home directory and the ones run here are the same code.
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import plistlib
import re
import shutil
import stat
import sys
import time
from datetime import datetime
from pathlib import Path

import pytest
from test_native_walk import _HELPER, _tree, needs_helper

from filecleaner import backups, leftovers, native_walk, plan, rules, scanner
from filecleaner import config as config_mod

_TOOL = Path(__file__).resolve().parent.parent / "tools" / "port_parity.py"
_RULES = [
    # Order matters: on an exact tie the earlier rule keeps the candidate.
    {"id": "logfiles", "include": ["**/*.log"], "exclude": ["skipme/**"], "min_age_days": 0},
    {"id": "alsologs", "include": ["projects/**/*.log"], "min_age_days": 0},
    {"id": "junkdirs", "include": ["**/junk"], "kind": "dir", "min_age_days": 0},
    {"id": "oldtmp", "include": ["**/*.tmp"], "min_age_days": 5},
    {"id": "bigbins", "include": ["**/*.bin"], "min_age_days": 0, "min_size_bytes": 500},
]
_SELECT = {"only_rules": {r["id"] for r in _RULES}, "include_disabled": True}


@pytest.fixture
def parity(monkeypatch):
    spec = importlib.util.spec_from_file_location("port_parity", _TOOL)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    monkeypatch.setattr(module, "helper", lambda: _HELPER)
    return module


def _grow(home: Path) -> None:
    _tree(home)
    ten_days_ago = time.time() - 10 * 86400
    (home / "top" / "old.tmp").write_bytes(b"o" * 9)
    os.utime(home / "top" / "old.tmp", (ten_days_ago, ten_days_ago))
    (home / "projects" / "app" / "junk" / "inner.log").write_bytes(b"nested in a candidate")
    (home / "projects" / "big.bin").write_bytes(b"B" * 600)
    (home / "projects" / "small.bin").write_bytes(b"b" * 499)


@needs_helper
class TestNativeScanMatchesTheReference:
    def test_same_candidates_as_the_python_scan(self, parity, sandbox_config, sandbox_home):
        _grow(sandbox_home)
        sandbox_config["rules"] = _RULES

        reference = parity.python_scan(sandbox_config, sandbox_home, **_SELECT)
        native = parity.rust_scan(sandbox_config, sandbox_home, **_SELECT)

        assert parity.summarise_rust(native) == parity.summarise_python(reference)
        assert native["overlaps_dropped"] == reference.overlaps_dropped
        by_path = {Path(c["path"]).name: c["rule_id"] for c in native["candidates"]}
        assert by_path == {
            "junk": "junkdirs",  # and everything inside it is coalesced away
            "build.log": "logfiles",  # matched by alsologs too; the earlier rule keeps it
            "unicode name.log": "logfiles",
            "old.tmp": "oldtmp",  # one.tmp is too young
            "big.bin": "bigbins",  # small.bin is one byte short
        }
        times = {str(c.path): c.mtime for c in reference.candidates}
        assert all(abs(c["mtime"] - times[c["path"]]) < 1e-3 for c in native["candidates"])

    def test_same_errors_as_the_python_scan(self, parity, sandbox_config, sandbox_home):
        _grow(sandbox_home)
        sandbox_config["rules"] = _RULES
        locked = sandbox_home / "projects" / "locked"
        locked.mkdir()
        locked.chmod(0)
        try:
            reference = parity.python_scan(sandbox_config, sandbox_home, **_SELECT)
            native = parity.rust_scan(sandbox_config, sandbox_home, **_SELECT)
        finally:
            locked.chmod(0o700)

        assert parity.summarise_rust(native) == parity.summarise_python(reference)
        assert any("Permission denied" in e for e in parity.summarise_rust(native)[1])

    def test_the_native_scan_refuses_protected_places_by_itself(self, parity, sandbox_config, sandbox_home):
        """In ``scan`` mode nothing downstream re-checks: the Rust deny-list is
        the authority, including for what only resolves into a protected place."""
        _grow(sandbox_home)
        (sandbox_home / "projects" / "sneaky").symlink_to(sandbox_home / ".ssh")
        sandbox_config["rules"] = _RULES

        native = parity.rust_scan(sandbox_config, sandbox_home, **_SELECT)

        reported = {c["path"] for c in native["candidates"]}
        assert not any("/.ssh/" in p or "/Library/Mail/" in p or "/.git/" in p or "/sneaky/" in p for p in reported)

    def test_the_reference_really_was_the_python_walker(self, parity, sandbox_config, sandbox_home, monkeypatch):
        _grow(sandbox_home)
        sandbox_config["rules"] = _RULES
        monkeypatch.setenv(native_walk.HELPER_ENV, str(_HELPER))
        seen: list[Path | None] = []
        real = native_walk.helper_path

        def spy() -> Path | None:
            seen.append(real())
            return seen[-1]

        monkeypatch.setattr(native_walk, "helper_path", spy)

        parity.python_scan(sandbox_config, sandbox_home, **_SELECT)

        assert seen and all(found is None for found in seen)  # asked for, and refused every time
        assert os.environ[native_walk.HELPER_ENV] == str(_HELPER)  # and the caller's setting is put back


# --------------------------------------------------------------------------
# Phase 2: config, rules, scan roots and the report, natively
# --------------------------------------------------------------------------

_NOW = 1_800_000_000.0  # both sides are told the time, so that they agree on every age

_CONFIG = """
retention_days = 14
mystery_key = "kept, with a warning"
protected_paths = ["~/projects/app/keepme"]
scan_roots = ["~", "{volume}"]

[rule_overrides]
logs = false
old_downloads = true

[rule_param_overrides.system_caches]
min_age_days = 0

[rule_param_overrides.trash]
min_size_bytes = 4

[[rules]]
id = "anylog"
include = ["**/*.log"]
exclude = ["skipme/**", "Library/**"]
min_age_days = 0

[[rules]]
id = "junkdirs"
label = "Junk folders"
category = "Mine"
description = "folders called junk — «ünïcödé»"
kind = "dir"
risk = "high"
include = "**/junk"
enabled = false
"""


def _age(path: Path, days: float) -> None:
    then = _NOW - days * 86400
    os.utime(path, (then, then), follow_symlinks=False)


def _world(home: Path, volume: Path) -> None:
    """Something for the builtin rules to find: both scopes, both kinds, an
    overlap, a tie between two rules, thresholds either side of the line,
    and names that need escaping."""
    _tree(home)
    files = {
        "Library/Logs/DiagnosticReports/crash.ips": (9, 1),  # crash_reports, and logs: the earlier rule keeps it
        "Library/Logs/app/old.log": (20, 30),
        "Library/Logs/app/new.log": (21, 1),  # too young for logs
        "Library/Caches/com.example.app/blob.bin": (4096, 10),
        "Library/Caches/pip/http/wheel.bin": (512, 10),  # dev_pip_cache, inside what system_caches takes whole
        ".Trash/thrown/away.txt": (30, 2),
        ".Trash/tiny/x": (1, 2),
        "Documents/.DS_Store": (6, 400),
        "Library/Preferences/.DS_Store": (6, 400),  # excluded: Library/**
        "Downloads/ancient.zip": (700, 120),
        "Downloads/recent.zip": (701, 5),
        "projects/web/node_modules/pkg/index.js": (33, 60),
        "projects/app/keepme/kept.log": (5, 50),  # under a protected path
        'Documents/we"ird\nname/.DS_Store': (6, 3),
    }
    for relative, (size, _days) in files.items():
        path = home / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b"x" * size)
    (volume / ".Trashes" / "501" / "gone").mkdir(parents=True)
    (volume / ".Trashes" / "501" / "gone" / "f.bin").write_bytes(b"v" * 77)
    # Age everything, deepest first, so that no later write freshens a folder.
    for top in (home, volume):
        for folder, _dirs, names in os.walk(top, topdown=False):
            for name in names:
                relative = str((Path(folder) / name).relative_to(top))
                _age(Path(folder) / name, files.get(relative, (0, 45))[1])
            _age(Path(folder), 45)
    for relative, (_size, days) in files.items():
        if days < 45:  # a folder is as young as the youngest thing in it
            _age((home / relative).parent, days)


@pytest.fixture
def world(sandbox_home, tmp_path):
    volume = tmp_path / "volume one"
    _world(sandbox_home, volume)
    config_mod.ensure_dirs()
    return sandbox_home, volume


def _configure(volume: Path) -> None:
    config_mod.CONFIG_FILE.write_text(_CONFIG.format(volume=volume), encoding="utf-8")


@needs_helper
class TestNativeReportsMatchByteForByte:
    @pytest.mark.parametrize(
        "select",
        [
            {},
            {"include_disabled": True},
            {"only_rules": {"anylog", "junkdirs", "trash", "external_trash", "logs"}},
            {"extra_excludes": ("Documents", "~/Downloads")},
        ],
        ids=["defaults", "include-disabled", "only-rules", "excludes"],
    )
    @pytest.mark.parametrize("configured", [False, True], ids=["no-config-file", "configured"])
    def test_scan_json(self, parity, world, select, configured):
        home, volume = world
        if configured:
            _configure(volume)
        elif "only_rules" in select:
            select = {"only_rules": {"trash", "logs", "ds_store"}}
        if "extra_excludes" in select:
            select = {"extra_excludes": (home / "Documents", Path("~/Downloads").expanduser())}

        python = parity.python_scan_json(home, now=_NOW, **select)
        native = parity.rust_scan_json(home, now=_NOW, **select)

        assert parity.without_duration(native) == parity.without_duration(python)
        assert json.loads(python)["candidate_count"] >= 3  # not two empty reports agreeing

    def test_scan_json_says_what_the_fixture_was_built_to_show(self, parity, world):
        home, volume = world
        _configure(volume)

        report = json.loads(parity.rust_scan_json(home, now=_NOW, include_disabled=True))

        found = {Path(c["path"]).name: c["rule_id"] for c in report["candidates"]}
        assert found["crash.ips"] == "crash_reports"  # a tie with `logs`: the earlier rule
        assert found["pip"] == "system_caches" and "http" not in found  # the shallower candidate, whole
        assert found["501"] == "external_trash" and report["scan_roots"] == [str(home), str(volume)]
        assert found["thrown"] == "trash" and "tiny" not in found  # min_size_bytes = 4, from the config
        assert found["ancient.zip"] == "old_downloads" and "recent.zip" not in found
        assert found["junk"] == "junkdirs" and found["node_modules"] == "dev_node_modules"
        assert "kept.log" not in found and "new.log" not in found
        assert report["overlaps_dropped"] >= 1
        assert [c for c in report["categories"] if c["category"] == "Mine"]
        assert any("\n" in c["path"] and '"' in c["path"] for c in report["candidates"])

    def test_scan_json_of_a_folder_that_is_not_home(self, parity, world):
        home, _volume = world
        python = parity.python_scan_json(home / "projects", now=_NOW, include_disabled=True)
        native = parity.rust_scan_json(home / "projects", now=_NOW, include_disabled=True)

        assert parity.without_duration(native) == parity.without_duration(python)
        assert json.loads(native)["scan_roots"] == [str(home / "projects")]

    def test_scan_json_reports_unreadable_folders_in_the_same_words(self, parity, world):
        home, volume = world
        _configure(volume)
        locked = home / "projects" / "locked"
        locked.mkdir()
        locked.chmod(0)
        try:
            python = parity.python_scan_json(home, now=_NOW)
            native = parity.rust_scan_json(home, now=_NOW)
        finally:
            locked.chmod(0o700)

        assert parity.without_duration(native) == parity.without_duration(python)
        assert any("Permission denied" in error for error in json.loads(native)["errors"])

    @pytest.mark.parametrize("configured", [False, True], ids=["no-config-file", "configured"])
    def test_config_json(self, parity, world, configured):
        if configured:
            _configure(world[1])

        assert parity.rust_config_json() == parity.python_config_json()

    def test_neither_writes_anything(self, parity, world):
        """The port never creates the config file; and a scan leaves no trace
        in the audit log (``fclean scan`` does — that comes with the command)."""
        parity.rust_scan_json(world[0], now=_NOW)
        parity.rust_config_json()

        assert not config_mod.CONFIG_FILE.exists()
        assert not config_mod.AUDIT_LOG_PATH.exists()  # (get_audit_log_path() would create it)

    @pytest.mark.parametrize(
        ("text", "python_error"),
        [
            ('retention_days = "soon"', config_mod.ConfigError),
            ("[rule_param_overrides.logs]\nmin_age_days = -1", config_mod.ConfigError),
            ('[[rules]]\nid = "logs"\ninclude = ["*"]', rules.RuleError),
            ('[[rules]]\nid = "mine"\ninclude = ["/etc/*"]', rules.RuleError),
            ("retention_days = = 3", config_mod.ConfigError),
        ],
    )
    def test_a_bad_config_is_refused_by_both(self, parity, world, text, python_error):
        config_mod.CONFIG_FILE.write_text(text, encoding="utf-8")

        with pytest.raises(python_error) as python:
            rules.load_custom_rules(config_mod.load_config())
        native = parity.rust("config-json", parity.native_request())

        assert native.returncode != 0 and native.stdout == ""
        if "not valid TOML" in str(python.value):  # the two parsers word the detail differently
            assert f"{config_mod.CONFIG_FILE} is not valid TOML: " in native.stderr
        else:
            assert str(python.value) in native.stderr

    def test_an_unknown_rule_is_refused_by_both(self, parity, world):
        with pytest.raises(scanner.UnknownRuleError) as python:
            scanner.select_rules(config_mod.load_config(), only_rules={"nope", "logs"})
        native = parity.rust("scan-json", parity.native_request(root=str(world[0]), only_rules=["nope", "logs"]))

        assert native.returncode != 0 and str(python.value) in native.stderr

    def test_the_json_writer_is_json_dumps(self, parity):
        assert parity.check_pyjson(4000)

    def test_both_read_the_same_builtin_rules(self, parity, world):
        report = json.loads(parity.rust_config_json())

        assert [r["id"] for r in report["rules"]] == [r.id for r in rules.BUILTIN_RULES]
        assert [{k: v for k, v in r.items() if k != "enabled"} for r in report["rules"]] == [
            r.to_dict() for r in rules.BUILTIN_RULES
        ]


# --------------------------------------------------------------------------
# Phase 3: the read-only commands
# --------------------------------------------------------------------------


def _awkward_ns(days_ago: float) -> int:
    """A time CPython and the helper spell differently as floats: one adds the
    two halves (``sec + 1e-9 * nsec``), the other divides the nanoseconds. About
    a quarter of all times are like this, so a port that knows only one formula
    is wrong about a quarter of all files."""
    ns = int((_NOW - days_ago * 86400) * 1e9) + 1
    while (ns // 10**9) + 1e-9 * (ns % 10**9) == ns / 1e9:
        ns += 4999
    return ns


def _files_world(home: Path) -> list[str]:
    """Every way one file is reached twice, contents that agree for the first
    64 KiB and beyond it, and paths that sort one way as paths and the other
    way as strings."""
    start = b"A" * 70000
    files = {
        "r/a/b/same.bin": b"dup-one " * 1000,
        "r/a-c/b/same.bin": b"dup-one " * 1000,  # sorts after r/a/... as a path, before it as a string
        "r/a/same2.bin": b"dup-one " * 1000,
        "r/big/x.bin": start + b"tail-X",
        "r/big/y.bin": start + b"tail-Y",  # the same first 64 KiB, and not a duplicate
        "r/big/x-copy.bin": start + b"tail-X",
        "r/Café/é.bin": b"unicode " * 900,
        "r/Café/z.bin": b"unicode " * 900,
        'r/odd/new\nline "q".bin': b"odd " * 2000,
        "r/odd/plain.bin": b"odd " * 2000,
        "r/small/tiny1": b"t" * 10,
        "r/small/tiny2": b"t" * 10,
        "r/empty1": b"",
        "r/empty2": b"",
        "r/unique.bin": bytes(range(256)) * 40,
        "other/same.bin": b"dup-one " * 1000,
        "r/projects/app/keepme/kept.bin": b"dup-one " * 1000,  # protected by the config below
    }
    for name, data in files.items():
        (home / name).parent.mkdir(parents=True, exist_ok=True)
        (home / name).write_bytes(data)
    os.link(home / "r/a/b/same.bin", home / "r/a/b/hard.bin")  # a second name, not a second file
    (home / "r/link.bin").symlink_to(home / "r/unique.bin")  # never followed
    (home / "alias").symlink_to(home / "r", target_is_directory=True)  # a root that is a symlink
    os.mkfifo(home / "r/fifo")
    for index, name in enumerate(sorted(files)):
        os.utime(home / name, ns=(_awkward_ns(40 + index),) * 2)
    config_mod.ensure_dirs()
    config_mod.CONFIG_FILE.write_text('protected_paths = ["~/r/projects/app/keepme"]\n', encoding="utf-8")
    return [str(home / "r"), str(home / "alias") + "/", "~/other"]


def _make_app(apps_dir: Path, name: str, bundle_id: str | None, fmt=plistlib.FMT_XML) -> None:
    contents = apps_dir / f"{name}.app" / "Contents"
    contents.mkdir(parents=True)
    if bundle_id is not None:
        (contents / "Info.plist").write_bytes(plistlib.dumps({"CFBundleIdentifier": bundle_id}, fmt=fmt))


def _leftovers_world(home: Path, apps_dir: Path, *, lone_folder: bool = False, extra_downloads: tuple[str, ...] = ()) -> None:
    _make_app(apps_dir, "Kept", "com.example.kept")
    _make_app(apps_dir, "Binary", "org.binary.app", plistlib.FMT_BINARY)
    _make_app(apps_dir, "NoPlist", None)
    (apps_dir / "Broken.app" / "Contents").mkdir(parents=True)
    (apps_dir / "Broken.app" / "Contents" / "Info.plist").write_bytes(b"not a plist at all")
    (apps_dir / "not-an-app").mkdir()
    support = home / "Library" / "Application Support"
    folders = ["Gone App"] if lone_folder else ["Gone App", "com.vanished.tool", "Young Orphan"]
    for name in [*folders, "com.example.kept.savedState", "Kept", "org.binary.app", "NoPlist"]:
        (support / name / "deep").mkdir(parents=True)
        (support / name / "deep" / "data.bin").write_bytes(b"d" * 1234)
        os.utime(support / name / "deep" / "data.bin", ns=(_awkward_ns(90),) * 2)
        os.utime(support / name / "deep", ns=(_awkward_ns(95),) * 2)
        os.utime(support / name, ns=(_awkward_ns(100),) * 2)
    if not lone_folder:
        os.utime(support / "Young Orphan" / "deep" / "data.bin", ns=(_awkward_ns(3),) * 2)
        # The folder itself is the newest thing in it: Python reads that time for itself.
        os.utime(support / "com.vanished.tool", ns=(_awkward_ns(45),) * 2)
    prefs = home / "Library" / "Preferences"
    prefs.mkdir(parents=True)
    (prefs / "com.vanished.tool.plist").write_bytes(b"p" * 77)  # an orphan that is a file
    os.utime(prefs / "com.vanished.tool.plist", ns=(_awkward_ns(200),) * 2)
    (prefs / "linked.plist").symlink_to(prefs / "com.vanished.tool.plist")
    downloads = home / "Downloads"
    downloads.mkdir()
    for name in ["Kept.dmg", "app.PKG", "Extracted.ZIP", "Unrelated.zip", "Kept.txt", *extra_downloads]:
        (downloads / name).write_bytes(b"i" * 321)
        os.utime(downloads / name, ns=(_awkward_ns(10),) * 2)
    (downloads / "Extracted").mkdir()
    (downloads / "Linked.dmg").symlink_to(downloads / "Kept.dmg")
    (downloads / "Folder.dmg").mkdir()


def _backups_world(base: Path) -> None:
    whole = datetime(2024, 2, 29, 12, 34, 56)
    devices = {
        "00008030-AAAA": ({"Device Name": "Marc's iPhone «é»", "Product Type": "iPhone15,2", "Last Backup Date": whole}, {"IsEncrypted": True}, plistlib.FMT_XML),
        "00008030-BBBB": ({"Device Name": "", "Last Backup Date": whole.replace(microsecond=250000)}, {"IsEncrypted": 0}, plistlib.FMT_BINARY),
        "00008030-CCCC": ({"Last Backup Date": "yesterday", "Product Type": "iPad8,1"}, {}, plistlib.FMT_BINARY),
        "00008030-DDDD": (None, {"IsEncrypted": "yes"}, plistlib.FMT_XML),
    }
    for udid, (info, manifest, fmt) in devices.items():
        (base / udid / "ab").mkdir(parents=True)
        (base / udid / "ab" / "blob").write_bytes(b"b" * (1000 + len(udid)))
        (base / udid / "Manifest.db").write_bytes(b"m" * 4096)
        (base / udid / "Manifest.plist").write_bytes(plistlib.dumps(manifest, fmt=fmt))
        if info is not None:
            (base / udid / "Info.plist").write_bytes(plistlib.dumps(info, fmt=fmt))
    (base / "00008030-DDDD" / "Info.plist").write_bytes(b"<plist>truncated")
    (base / ".DS_Store").write_bytes(b"x")  # not a folder, not a backup
    (base / "linked-backup").symlink_to(base / "00008030-AAAA", target_is_directory=True)


_AUDIT_LOG = "\n".join(
    [
        '{"timestamp": "2026-09-01T10:00:00+00:00", "action": "scan", "candidate_count": 3, "duration_seconds": 0.1}',
        "",
        "not json at all",
        "[1, 2, 3]",
        '  {"timestamp": "2026-09-02T10:00:00+00:00", "action": "purge", "paths": ["/a/é", "/b/\\u00e9"], "n": 1e16}  ',
        '{"action": "scan", "z": 1, "a": {"nested": [true, false, null, -0.5, 1e-7]}, "z": "said twice"}',
        '{"action": "scan", "note": "cut in two by a line separator inside a string"}',
        '{"action": "restore", "size": 18446744073709551615, "negative": -9223372036854775808}',
        '{"action": "scan", "trailing": "garbage"} extra',
        '{"action": "scan", "last": true}',
    ]
)


@needs_helper
class TestNativeReadOnlyCommandsMatchByteForByte:
    @pytest.mark.parametrize("options", [{}, {"top": 3}, {"top": 4, "min_size": 5000}], ids=["defaults", "top", "min-size"])
    def test_large_files(self, parity, sandbox_home, options):
        roots = _files_world(sandbox_home)

        python = parity.python_large_files_json(roots, **options)

        assert parity.rust_large_files_json(roots, **options) == python
        assert len(json.loads(python)["files"]) >= 3

    @pytest.mark.parametrize(
        "options", [{}, {"min_size": 0}, {"top": 1}, {"top": 0, "min_size": 1}], ids=["defaults", "every-size", "top", "no-limit"]
    )
    def test_duplicates(self, parity, sandbox_home, options):
        roots = _files_world(sandbox_home)

        python = parity.python_duplicates_json(roots, **options)

        assert parity.rust_duplicates_json(roots, **options) == python
        assert json.loads(python)["total_wasted_bytes"] > 0

    def test_duplicates_say_what_the_fixture_was_built_to_show(self, parity, sandbox_home):
        roots = _files_world(sandbox_home)

        report = json.loads(parity.rust_duplicates_json(roots, min_size=0, top=0))

        groups = {tuple(Path(p).relative_to(sandbox_home).as_posix() for p in g["paths"]) for g in report["groups"]}
        assert ("other/same.bin", "r/a/b/hard.bin", "r/a/same2.bin", "r/a-c/b/same.bin") in groups  # in Path order
        assert ("r/big/x-copy.bin", "r/big/x.bin") in groups  # y.bin agrees for 64 KiB and no further
        assert ("r/Café/z.bin", "r/Café/é.bin") in groups and ("r/empty1", "r/empty2") in groups
        named = {name for group in groups for name in group}
        assert not {n for n in named if "keepme" in n or n.startswith("alias") or n.endswith(("link.bin", "fifo"))}
        assert hashlib.sha256(b"").hexdigest() in {g["sha256"] for g in report["groups"]}

    @pytest.mark.parametrize("kind", ["apps", "installers", "all"])
    @pytest.mark.parametrize("lone_folder", [False, True], ids=["sized-by-the-helper", "one-folder-sized-by-python"])
    def test_leftovers(self, parity, sandbox_home, tmp_path, monkeypatch, kind, lone_folder):
        monkeypatch.setattr(leftovers, "_APPLICATIONS_DIRS", (tmp_path / "Applications", tmp_path / "no such folder"))
        _leftovers_world(sandbox_home, tmp_path / "Applications", lone_folder=lone_folder)

        python = parity.python_leftovers_json(kind, now=_NOW)

        assert parity.rust_leftovers_json(kind, now=_NOW) == python
        assert json.loads(python)["candidates"]

    def test_leftovers_say_what_the_fixture_was_built_to_show(self, parity, sandbox_home, tmp_path, monkeypatch):
        monkeypatch.setattr(leftovers, "_APPLICATIONS_DIRS", (tmp_path / "Applications",))
        _leftovers_world(sandbox_home, tmp_path / "Applications")

        found = {Path(c["path"]).name: c for c in json.loads(parity.rust_leftovers_json("all", now=_NOW))["candidates"]}

        assert set(found) == {"Gone App", "com.vanished.tool", "com.vanished.tool.plist", "Kept.dmg", "app.PKG", "Extracted.ZIP"}
        assert found["Gone App"]["size_bytes"] == 1234 and found["Gone App"]["is_dir"]
        assert found["com.vanished.tool.plist"]["size_bytes"] == 77 and found["Kept.dmg"]["risk"] == "medium"
        # The newest time in a folder comes from the helper; the folder's own, when it is the newest, from Python.
        assert found["Gone App"]["mtime"] == _awkward_ns(90) / 1e9
        own = _awkward_ns(45)
        assert found["com.vanished.tool"]["mtime"] == (own // 10**9) + 1e-9 * (own % 10**9) != own / 1e9

    @pytest.mark.skipif(sys.version_info < (3, 14), reason="Path.suffix is posixpath.splitext only since Python 3.14")
    def test_names_whose_only_dots_lead_or_trail(self, parity, sandbox_home, tmp_path, monkeypatch):
        """The port follows the newest Python. Before 3.14, ``Path("..zip")`` had
        the suffix ``.zip`` and the stem ``.`` — and was then "already
        extracted", ``Downloads/.`` being a folder — and ``Path("Foo.")`` had no
        suffix at all."""
        monkeypatch.setattr(leftovers, "_APPLICATIONS_DIRS", (tmp_path / "Applications",))
        _leftovers_world(sandbox_home, tmp_path / "Applications", extra_downloads=("..zip", "Kept.", ".dmg"))
        _make_app(tmp_path / "Applications", "Trailing.", "com.example.trailing")

        python = parity.python_leftovers_json("all", now=_NOW)

        assert parity.rust_leftovers_json("all", now=_NOW) == python
        assert not {"..zip", "Kept.", ".dmg"} & {Path(c["path"]).name for c in json.loads(python)["candidates"]}

    def test_backups(self, parity, sandbox_home):
        base = backups.default_backup_root()
        assert json.loads(parity.rust_backups_json()) == {"backups": []}  # no folder at all
        _backups_world(base)

        python = parity.python_backups_json()

        assert parity.rust_backups_json() == python
        assert parity.rust_backups_json(base) == parity.python_backups_json(base)
        listed = {b["udid"]: b for b in json.loads(python)["backups"]}
        assert listed["00008030-AAAA"]["last_backup_date"] == "2024-02-29T12:34:56" and listed["00008030-AAAA"]["encrypted"]
        assert listed["00008030-BBBB"]["last_backup_date"] == "2024-02-29T12:34:56.250000"
        assert listed["00008030-BBBB"]["device_name"] == "00008030-BBBB" and not listed["00008030-BBBB"]["encrypted"]
        assert listed["00008030-CCCC"]["last_backup_date"] is None and listed["00008030-DDDD"]["encrypted"]
        assert set(listed) == {"00008030-AAAA", "00008030-BBBB", "00008030-CCCC", "00008030-DDDD", "linked-backup"}

    @pytest.mark.parametrize(("limit", "action"), [(50, None), (0, None), (2, None), (1, "scan"), (0, "purge"), (5, "never")])
    def test_audit(self, parity, sandbox_home, limit, action):
        config_mod.ensure_dirs()
        config_mod.AUDIT_LOG_PATH.write_text(_AUDIT_LOG, encoding="utf-8")

        python = parity.python_audit_json(limit, action)

        assert parity.rust_audit_json(limit, action) == python
        assert (action == "never") == (json.loads(python)["entries"] == [])

    def test_an_audit_log_that_is_not_there_is_empty_and_stays_away(self, parity, sandbox_home):
        assert json.loads(parity.rust_audit_json()) == {"entries": []}
        assert not config_mod.AUDIT_LOG_PATH.exists()  # Python's reader would have created it

    def test_each_accepts_the_plan_the_other_writes(self, parity, world, tmp_path):
        home, volume = world
        _configure(volume)
        (home / "Documents" / "Café ü").mkdir()
        (home / "Documents" / "Café ü" / ".DS_Store").write_bytes(b"x" * 6)
        _age(home / "Documents" / "Café ü" / ".DS_Store", 400)
        by_python, by_rust = tmp_path / "plans" / "python.json", tmp_path / "plans" / "rust.json"
        parity.python_save_plan(by_python, home, now=_NOW, created_at="2026-09-19T00:00:00+00:00", include_disabled=True)
        parity.rust_save_plan(by_rust, home, now=_NOW, created_at="2026-09-19T00:00:00+00:00", include_disabled=True)

        assert by_rust.read_bytes() == by_python.read_bytes()
        assert "Caf\\u00e9 \\u00fc" in by_rust.read_text(encoding="ascii")  # json.dumps' ensure_ascii, not the reports'
        assert stat.S_IMODE(by_rust.stat().st_mode) == 0o600 and not by_rust.with_name("rust.json.tmp").exists()
        untouched = parity.python_plan_check_json(by_rust)
        assert parity.rust_plan_check_json(by_python) == untouched and json.loads(untouched)["stale"] == []

        # Then the world moves on, in each of the ways a plan can go stale.
        planned = {Path(c["path"]).name: Path(c["path"]) for c in json.loads(by_python.read_text())["candidates"]}
        planned["old.log"].write_bytes(b"grown since it was reviewed")
        planned["ancient.zip"].unlink()
        (planned["node_modules"] / "pkg" / "added.js").write_bytes(b"new")
        shutil.rmtree(planned["thrown"])
        planned["thrown"].write_bytes(b"a file where a folder was")
        planned["crash.ips"].unlink()
        planned["crash.ips"].symlink_to(home / "Documents")

        for plan_file in (by_python, by_rust):
            python = parity.python_plan_check_json(plan_file)
            assert parity.rust_plan_check_json(plan_file) == python
        reasons = {Path(s["path"]).name: s["reason"] for s in json.loads(python)["stale"]}
        assert reasons == {
            "old.log": "modified since the plan was written",
            "ancient.zip": "no longer exists",
            "node_modules": "modified since the plan was written",
            "thrown": "changed between file and directory",
            "crash.ips": "is now a symlink",
        }
        assert len(json.loads(python)["fresh"]) >= 3

    @pytest.mark.parametrize(
        ("text", "python_error"),
        [
            ("{not json", "is not valid JSON"),
            ("[1, 2]", "expected a JSON object"),
            ('{"format_version": 2, "candidates": []}', "unsupported plan format_version 2 (expected 1)"),
            ('{"format_version": "1", "candidates": []}', "unsupported plan format_version '1' (expected 1)"),
            ('{"candidates": []}', "unsupported plan format_version None (expected 1)"),
            ('{"format_version": 1}', "malformed plan file: 'candidates'"),
            ('{"format_version": 1, "candidates": [{"path": "/x"}]}', "malformed plan file: 'size_bytes'"),
        ],
    )
    def test_a_bad_plan_is_refused_by_both(self, parity, sandbox_home, tmp_path, text, python_error):
        bad = tmp_path / "bad.json"
        bad.write_text(text, encoding="utf-8")

        with pytest.raises(plan.PlanError, match=re.escape(python_error)):
            parity.python_plan_check_json(bad)
        with pytest.raises(RuntimeError, match=re.escape(python_error)):
            parity.rust_plan_check_json(bad)
        with pytest.raises(RuntimeError, match="cannot read"):
            parity.rust_plan_check_json(tmp_path / "no such plan.json")

    @pytest.mark.parametrize(
        "coerced",
        ['"size_bytes": "12"', '"is_dir": 0', '"mtime": "5.0"', '"path": 12'],
    )
    def test_the_port_refuses_what_python_would_coerce(self, parity, sandbox_home, tmp_path, coerced):
        """Stricter, never looser (docs/PORT.md): a hand-edited plan whose
        values are the wrong type is read by Python and refused here."""
        fields = {"path": '"/nowhere"', "size_bytes": "12", "is_dir": "false", "mtime": "5.0", "rule_id": '"r"', "category": '"c"'}
        fields[coerced.split('"')[1]] = coerced.split(": ", 1)[1]
        candidate = ", ".join(f'"{key}": {value}' for key, value in fields.items())
        edited = tmp_path / "edited.json"
        edited.write_text(f'{{"format_version": 1, "candidates": [{{{candidate}}}]}}', encoding="utf-8")

        assert json.loads(parity.python_plan_check_json(edited))["stale"][0]["reason"] == "no longer exists"
        with pytest.raises(RuntimeError, match="malformed plan file"):
            parity.rust_plan_check_json(edited)

    def test_limits_python_mishandles_are_refused_by_name(self, parity, sandbox_home):
        """``--top 0`` is an IndexError in ``large-files``; a negative ``--top``
        or ``--limit`` makes Python slice from the wrong end."""
        roots = _files_world(sandbox_home)
        with pytest.raises(IndexError):
            parity.python_large_files_json(roots, top=0)
        for refused, message in (
            (lambda: parity.rust_large_files_json(roots, top=0), "--top must be at least 1"),
            (lambda: parity.rust_duplicates_json(roots, top=-1), "--top must not be negative"),
            (lambda: parity.rust_audit_json(-1), "--limit must not be negative"),
        ):
            with pytest.raises(RuntimeError, match=message):
                refused()

    def test_none_of_them_writes_anything(self, parity, sandbox_home, tmp_path, monkeypatch):
        monkeypatch.setattr(leftovers, "_APPLICATIONS_DIRS", (tmp_path / "Applications",))
        roots = _files_world(sandbox_home)
        _leftovers_world(sandbox_home, tmp_path / "Applications")
        _backups_world(backups.default_backup_root())
        before = {p: p.lstat().st_mtime_ns for p in tmp_path.rglob("*")}

        parity.rust_large_files_json(roots)
        parity.rust_duplicates_json(roots, min_size=0)
        parity.rust_leftovers_json("all", now=_NOW)
        parity.rust_backups_json()
        parity.rust_audit_json()

        assert {p: p.lstat().st_mtime_ns for p in tmp_path.rglob("*")} == before
