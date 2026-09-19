"""Conformance tests for ``safety.is_protected``.

The cases live in ``safety_cases.json`` — a flat, language-neutral list of
path/expected pairs plus the fixture tree they need — so that a port of the
deny-list to another language can run the exact same table. This file is
only the Python harness for it, plus a few Python-specific checks.
"""

from __future__ import annotations

import json
import unicodedata
from pathlib import Path
from typing import Any

import pytest

from filecleaner import safety

_TABLE: dict[str, Any] = json.loads((Path(__file__).parent / "safety_cases.json").read_text())
_CASES: list[dict[str, Any]] = _TABLE["cases"]


def _swapcase_last(path: Path) -> str:
    return str(path.parent / path.name.swapcase())


class _World:
    """The fixture tree described by the table's ``setup`` block."""

    def __init__(self, tmp: Path) -> None:
        # Escapes, not literals: an editor must not be able to renormalise this.
        home = tmp / "h\u00f4me-\u00e9"
        self_dir = Path(safety.__file__).resolve().parent
        self.home = home
        self.volumes = tmp / "Volumes"
        self.placeholders = {
            "{TMP}": str(tmp),
            "{HOME}": str(home),
            "{HOME_NFD}": str(home.parent / unicodedata.normalize("NFD", home.name)),
            "{HOME_SWAPCASE}": _swapcase_last(home),
            "{VOLUMES}": str(self.volumes),
            "{SELF}": str(self_dir),
            "{SELF_SWAPCASE}": _swapcase_last(self_dir),
        }
        probe = tmp / "CaseProbe"
        probe.mkdir()
        self.case_insensitive_fs = (tmp / "caseprobe").exists()

    def expand(self, text: str) -> str:
        for name, value in self.placeholders.items():
            text = text.replace(name, value)
        return text

    def build(self) -> None:
        for d in _TABLE["setup"]["dirs"]:
            Path(self.expand(d)).mkdir(parents=True, exist_ok=True)
        for link in _TABLE["setup"]["symlinks"]:
            link_path = Path(self.expand(link["link"]))
            link_path.parent.mkdir(parents=True, exist_ok=True)
            link_path.symlink_to(self.expand(link["target"]))


@pytest.fixture(scope="module")
def world(tmp_path_factory: pytest.TempPathFactory) -> _World:
    # Built once per module: the tree is read-only as far as the cases go.
    w = _World(tmp_path_factory.mktemp("safety").resolve())
    w.build()
    return w


@pytest.fixture
def in_world(world: _World, monkeypatch: pytest.MonkeyPatch) -> _World:
    monkeypatch.setattr(Path, "home", lambda: world.home)
    monkeypatch.setenv("HOME", str(world.home))
    monkeypatch.setattr(safety, "_VOLUMES_DIR", world.volumes)
    monkeypatch.chdir(world.home)
    safety.reset_caches()
    return world


def _case_id(case: dict[str, Any]) -> str:
    return f"{case['group']}:{case['path']}".encode("ascii", "backslashreplace").decode()


@pytest.mark.parametrize("case", _CASES, ids=_case_id)
def test_table(case: dict[str, Any], in_world: _World) -> None:
    if case.get("requires") == "case-insensitive-fs" and not in_world.case_insensitive_fs:
        pytest.skip("needs a case-insensitive filesystem")
    path = Path(in_world.expand(case["path"]))
    extra = tuple(Path(in_world.expand(p)) for p in case.get("extra_protected", ()))
    assert safety.is_protected(path, extra_protected=extra) is case["protected"], case.get("note", "")


def test_table_covers_every_deny_entry() -> None:
    """Adding a deny entry without adding its rows to the table must fail
    here, not silently ship untested."""
    paths_by_group: dict[str, set[str]] = {}
    for case in _CASES:
        paths_by_group.setdefault(case["group"], set()).add(case["path"])

    def covered(prefix: str, entries: tuple[str, ...], base: str) -> None:
        for entry in entries:
            for kind, spelled in (("exact", entry), ("case-variant", f"{entry.upper()}/child")):
                assert f"{base}{spelled}" in paths_by_group[f"{prefix}/{kind}"], (prefix, kind, entry)
            assert any(
                c["group"] == f"{prefix}/symlink-into" and c.get("note", "").endswith(entry) for c in _CASES
            ), (prefix, "symlink-into", entry)

    covered("absolute", safety.ABSOLUTE_DENY_PATHS, "")
    covered("volume", safety.RELATIVE_DENY_SUBPATHS, "{VOLUMES}/Ext/")
    covered("home", safety.HOME_DENY_SUBPATHS, "{HOME}/")


def test_unresolvable_path_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """If a path cannot even be resolved, nothing about it can be proven
    safe — it must be treated as protected rather than waved through."""

    def boom(self: Path, strict: bool = False) -> Path:
        raise RuntimeError("Symlink loop")

    monkeypatch.setattr(Path, "resolve", boom)
    assert safety.is_protected(tmp_path / "anything")


def test_symlink_loop_outside_deny_paths_does_not_crash(tmp_path: Path) -> None:
    (tmp_path / "a").symlink_to(tmp_path / "b")
    (tmp_path / "b").symlink_to(tmp_path / "a")
    assert safety.is_protected(tmp_path / "a") in (True, False)


def test_volume_mounted_mid_run_is_picked_up_after_the_ttl(in_world: _World, monkeypatch: pytest.MonkeyPatch) -> None:
    late = in_world.volumes / "LateMount"
    target = late / "System" / "x"
    monkeypatch.setattr(safety, "_VOLUME_CACHE_TTL_SECONDS", 3600.0)
    safety.reset_caches()
    assert not safety.is_protected(target)
    late.mkdir()
    try:
        assert not safety.is_protected(target)  # the mount list is still cached
        monkeypatch.setattr(safety, "_VOLUME_CACHE_TTL_SECONDS", 0.0)
        assert safety.is_protected(target)  # expired -> re-enumerated
    finally:
        late.rmdir()


def test_is_within_allowed_roots(tmp_path: Path) -> None:
    root = tmp_path / "root"
    root.mkdir()
    inside = root / "sub" / "file.txt"
    inside.parent.mkdir(parents=True)
    inside.write_text("x")
    outside = tmp_path / "elsewhere"
    outside.mkdir()

    assert safety.is_within_allowed_roots(inside, (root,))
    assert not safety.is_within_allowed_roots(outside, (root,))


def test_allowed_roots_stay_case_sensitive(tmp_path: Path) -> None:
    """The allow-list is the opposite polarity to the deny-list: folding
    case there would make it *looser*. A case-variant candidate is refused
    ("outside the scanned roots"), which is the safe direction."""
    root = tmp_path / "Root"
    (root / "sub").mkdir(parents=True)
    assert not safety.is_within_allowed_roots(tmp_path / "ROOT" / "sub", (root,))
