"""The Rust port against the Python it is a port of (docs/PORT.md).

Phase 1: ``fclean-walk scan`` does the whole scan natively — walk, protection
re-check, thresholds, coalescing — and must produce exactly what
``scanner.run_scan`` does with the pure-Python walker.

Phase 2: ``scan-json`` and ``config-json`` read the config file, the rules
and the volumes for themselves and must print, byte for byte, what
``fclean scan --json`` and ``fclean config show --json`` print.

The comparisons live in ``tools/port_parity.py`` so that the checks run by
hand on a real home directory and the ones run here are the same code.
"""

from __future__ import annotations

import importlib.util
import json
import os
import time
from pathlib import Path

import pytest
from test_native_walk import _HELPER, _tree, needs_helper

from filecleaner import config as config_mod
from filecleaner import native_walk, rules, scanner

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
