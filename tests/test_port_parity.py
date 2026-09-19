"""Phase 1 of the Rust port (docs/PORT.md): ``fclean-walk scan`` does the
whole scan natively — walk, protection re-check, thresholds, coalescing —
and must produce exactly what ``scanner.run_scan`` does with the pure-Python
walker. The comparison itself lives in ``tools/port_parity.py`` so the check
run by hand on a real home directory and the one run here are the same code.
"""

from __future__ import annotations

import importlib.util
import os
import time
from pathlib import Path

import pytest
from test_native_walk import _HELPER, _tree, needs_helper

from filecleaner import native_walk

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
