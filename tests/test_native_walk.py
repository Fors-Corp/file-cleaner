"""The native scan walker (``native/fclean-walk``) and its Python client.

Two halves. The first needs no compiled helper: it drives the client with
small fake helpers to pin the trust boundary (a helper can be wrong, or
hostile, or broken — none of that may reach a candidate list). The second
runs the real helper against the Python walker, which is the reference,
and is skipped when the helper has not been built.
"""

from __future__ import annotations

import json
import os
import shlex
import stat
import subprocess
import sys
import warnings
from pathlib import Path

import pytest

from filecleaner import duplicates, filewalk, largefiles, native_walk, safety, scanner

_REPO = Path(__file__).resolve().parent.parent
_RULES = [
    {"id": "logfiles", "include": ["**/*.log"], "exclude": ["skipme/**"], "min_age_days": 0},
    {"id": "junkdirs", "include": ["**/junk"], "kind": "dir", "min_age_days": 0},
    {"id": "shallow", "include": ["top/*.tmp"], "min_age_days": 0},
]


def _fake_helper(tmp_path: Path, body: str) -> Path:
    program = tmp_path / "fake_fclean_walk.py"
    program.write_text(f"import json, sys\nrequest = json.load(sys.stdin)\n{body}\n")
    # A /bin/sh wrapper rather than a Python shebang: the interpreter's path
    # may contain spaces, which a shebang line cannot express.
    script = tmp_path / "fake-fclean-walk"
    script.write_text(f"#!/bin/sh\nexec {shlex.quote(sys.executable)} {shlex.quote(str(program))}\n")
    script.chmod(script.stat().st_mode | stat.S_IXUSR)
    return script


def _emit_lines(lines: list[dict]) -> str:
    return "\n".join(f"print({json.dumps(json.dumps(line))})" for line in lines)


def _tree(home: Path) -> None:
    (home / "projects" / "app" / "junk" / "deep").mkdir(parents=True)
    (home / "projects" / "app" / "junk" / "a.bin").write_bytes(b"x" * 300)
    (home / "projects" / "app" / "junk" / "deep" / "b.bin").write_bytes(b"y" * 700)
    (home / "projects" / "app" / "build.log").write_bytes(b"l" * 11)
    (home / "projects" / "app" / ".git").mkdir()
    (home / "projects" / "app" / ".git" / "never.log").write_bytes(b"g")
    (home / "skipme").mkdir()
    (home / "skipme" / "excluded.log").write_bytes(b"e")
    (home / "top" / "nested").mkdir(parents=True)
    (home / "top" / "one.tmp").write_bytes(b"t" * 5)
    (home / "top" / "nested" / "too-deep.tmp").write_bytes(b"t")
    (home / ".ssh").mkdir()
    (home / ".ssh" / "debug.log").write_bytes(b"secret")
    (home / "Library" / "Mail").mkdir(parents=True)
    (home / "Library" / "Mail" / "mail.log").write_bytes(b"secret")
    (home / "linked").symlink_to(home / "projects")
    (home / "café [1]").mkdir()
    (home / "café [1]" / "unicode name.log").write_bytes(b"u" * 3)


def _scan(config: dict, home: Path) -> scanner.ScanResult:
    config["rules"] = _RULES
    return scanner.run_scan(
        config, only_rules={"logfiles", "junkdirs", "shallow"}, include_disabled=True, root=home
    )


def _summary(result: scanner.ScanResult) -> set[tuple[str, bool, int, str]]:
    return {(str(c.path), c.is_dir, c.size_bytes, c.rule_id) for c in result.candidates}


# --------------------------------------------------------------------------
# The client and the trust boundary (no compiled helper needed)
# --------------------------------------------------------------------------


class TestHelperSelection:
    def test_off_by_default_when_nothing_is_installed(self, monkeypatch, tmp_path):
        monkeypatch.delenv(native_walk.HELPER_ENV, raising=False)
        monkeypatch.setattr(native_walk, "_BUNDLED_HELPER", tmp_path / "absent")
        assert native_walk.helper_path() is None

    @pytest.mark.parametrize("value", ["0", "off", "OFF", "false", ""])
    def test_can_be_switched_off(self, monkeypatch, tmp_path, value):
        monkeypatch.setattr(native_walk, "_BUNDLED_HELPER", _fake_helper(tmp_path, "pass"))
        monkeypatch.setenv(native_walk.HELPER_ENV, value)
        assert native_walk.helper_path() is None

    def test_is_never_looked_up_on_path(self, monkeypatch, tmp_path):
        _fake_helper(tmp_path, "pass").rename(tmp_path / "fclean-walk")
        monkeypatch.setenv("PATH", f"{tmp_path}{os.pathsep}{os.environ['PATH']}")
        monkeypatch.delenv(native_walk.HELPER_ENV, raising=False)
        monkeypatch.setattr(native_walk, "_BUNDLED_HELPER", tmp_path / "absent")
        assert native_walk.helper_path() is None

    def test_a_non_executable_file_is_not_a_helper(self, monkeypatch, tmp_path):
        plain = tmp_path / "fclean-walk"
        plain.write_text("not a program")
        monkeypatch.setenv(native_walk.HELPER_ENV, str(plain))
        assert native_walk.helper_path() is None


class TestUntrustedHelper:
    def test_a_lying_helper_cannot_produce_a_protected_or_outside_candidate(
        self, sandbox_config, sandbox_home, tmp_path, monkeypatch
    ):
        _tree(sandbox_home)
        honest = sandbox_home / "projects" / "app" / "build.log"
        claims = [
            {"m": 0, "p": str(sandbox_home / ".ssh" / "debug.log"), "d": False, "s": 6, "t": 1.0},
            {"m": 0, "p": str(sandbox_home / ".SSH" / "debug.log"), "d": False, "s": 6, "t": 1.0},
            {"m": 0, "p": str(sandbox_home / "linked" / ".." / ".ssh" / "debug.log"), "d": False, "s": 6, "t": 1.0},
            {"m": 0, "p": "/etc/hosts", "d": False, "s": 6, "t": 1.0},
            {"m": 0, "p": str(sandbox_home.parent / "elsewhere.log"), "d": False, "s": 6, "t": 1.0},
            {"m": 0, "p": str(sandbox_home), "d": True, "s": 6, "t": 1.0},
            {"m": 0, "p": str(honest), "d": False, "s": 11, "t": 1.0},
            {"done": 1},
        ]
        monkeypatch.setenv(native_walk.HELPER_ENV, str(_fake_helper(tmp_path, _emit_lines(claims))))

        result = _scan(sandbox_config, sandbox_home)

        assert [c.path for c in result.candidates] == [honest]

    def test_a_helper_cannot_bypass_a_rules_thresholds(self, sandbox_config, sandbox_home, tmp_path, monkeypatch):
        _tree(sandbox_home)
        target = sandbox_home / "projects" / "app" / "build.log"
        fresh = [{"m": 0, "p": str(target), "d": False, "s": 11, "t": 4102444800.0}, {"done": 1}]  # mtime in 2100
        monkeypatch.setenv(native_walk.HELPER_ENV, str(_fake_helper(tmp_path, _emit_lines(fresh))))
        sandbox_config["rules"] = [{"id": "logfiles", "include": ["**/*.log"], "min_age_days": 30}]

        result = scanner.run_scan(sandbox_config, only_rules={"logfiles"}, include_disabled=True, root=sandbox_home)

        assert result.candidates == []

    @pytest.mark.parametrize(
        ("body", "why"),
        [
            ("sys.exit(3)", "exit status 3"),
            ("sys.stderr.write('boom'); sys.exit(2)", "boom"),
            ('print(json.dumps({"m": 0, "p": "/x", "d": False, "s": 1, "t": 1.0}))', "exit status 0"),  # no "done"
            ("print('this is not json')", "unreadable output"),
            ('print(json.dumps({"m": 99, "p": "/x", "d": False, "s": 1, "t": 1.0})); print(json.dumps({"done": 1}))',
             "never requested"),
        ],
    )
    def test_a_broken_helper_falls_back_to_the_python_walker(
        self, sandbox_config, sandbox_home, tmp_path, monkeypatch, body, why
    ):
        _tree(sandbox_home)
        monkeypatch.setenv(native_walk.HELPER_ENV, "0")
        expected = _summary(_scan(sandbox_config, sandbox_home))
        assert expected  # the fixture tree does produce candidates

        monkeypatch.setenv(native_walk.HELPER_ENV, str(_fake_helper(tmp_path, body)))
        with pytest.warns(RuntimeWarning, match=why):
            result = _scan(sandbox_config, sandbox_home)

        assert _summary(result) == expected

    def test_no_helper_means_no_warning(self, sandbox_config, sandbox_home, monkeypatch):
        _tree(sandbox_home)
        monkeypatch.setenv(native_walk.HELPER_ENV, "0")
        with warnings.catch_warnings():
            warnings.simplefilter("error")
            assert _scan(sandbox_config, sandbox_home).candidates

    def test_progress_comes_from_the_helpers_running_total(self, sandbox_config, sandbox_home, tmp_path, monkeypatch):
        _tree(sandbox_home)
        lines = [{"n": 2048, "w": 0, "r": "projects/app"}, {"done": 4000}]
        monkeypatch.setenv(native_walk.HELPER_ENV, str(_fake_helper(tmp_path, _emit_lines(lines))))
        sandbox_config["rules"] = _RULES
        seen: list[tuple[str, float | None]] = []

        scanner.run_scan(
            sandbox_config,
            only_rules={"logfiles"},
            include_disabled=True,
            root=sandbox_home,
            progress=lambda message, percent: seen.append((message, percent)),
        )

        assert ("2,048 folders · logfiles: scanning projects/app", None) in seen


class TestUntrustedFileWalk:
    """The same boundary for the `files` walk behind duplicates/large-files."""

    @staticmethod
    def _helper_claiming(tmp_path, monkeypatch, claims):
        lines = [*claims, {"done": len(claims)}]
        monkeypatch.setenv(native_walk.HELPER_ENV, str(_fake_helper(tmp_path, _emit_lines(lines))))

    def test_one_file_reported_under_two_names_is_not_a_duplicate(
        self, sandbox_config, sandbox_home, tmp_path, monkeypatch
    ):
        """The bug 1.5.2 fixed, replayed by a helper that fails to tell one
        file from two. Python still decides what a duplicate is."""
        docs = sandbox_home / "Docs"
        docs.mkdir()
        only = docs / "only-copy.bin"
        only.write_bytes(b"z" * 5000)
        alias = sandbox_home / "docs-alias"
        alias.symlink_to(docs)
        self._helper_claiming(
            tmp_path,
            monkeypatch,
            [
                {"f": str(only), "r": 0, "s": 5000, "t": 1.0},
                {"f": str(alias / "only-copy.bin"), "r": 0, "s": 5000, "t": 1.0},
            ],
        )

        groups = duplicates.find_duplicates([sandbox_home], sandbox_config, min_size_bytes=1)

        assert groups == []
        assert only.read_bytes() == b"z" * 5000

    def test_files_outside_the_roots_or_in_protected_places_are_dropped(
        self, sandbox_config, sandbox_home, tmp_path, monkeypatch
    ):
        _tree(sandbox_home)
        honest = sandbox_home / "projects" / "app" / "junk" / "a.bin"
        self._helper_claiming(
            tmp_path,
            monkeypatch,
            [
                {"f": str(sandbox_home / ".ssh" / "debug.log"), "r": 0, "s": 6, "t": 1.0},
                {"f": str(sandbox_home / "Library" / "Mail" / "mail.log"), "r": 0, "s": 6, "t": 1.0},
                {"f": "/etc/hosts", "r": 0, "s": 6, "t": 1.0},
                {"f": str(sandbox_home.parent / "elsewhere.bin"), "r": 0, "s": 6, "t": 1.0},
                {"f": str(honest), "r": 0, "s": 1, "t": 1.0},  # under-reports its size ...
                {"f": str(honest), "r": 0, "s": 300, "t": 1.0},
            ],
        )

        found = list(filewalk.walk_unique_files([sandbox_home], min_size=100))

        assert found == [(honest, filewalk.FileStat(300, 1.0))]  # ... and the min-size floor is Python's too

    @pytest.mark.parametrize(
        "body", ["sys.exit(3)", "print('not json')", 'print(json.dumps({"f": "/x", "r": 7, "s": 1, "t": 1.0})); print(json.dumps({"done": 1}))']
    )
    def test_a_broken_helper_falls_back_to_the_python_walk(self, sandbox_home, tmp_path, monkeypatch, body):
        _tree(sandbox_home)
        monkeypatch.setenv(native_walk.HELPER_ENV, "0")
        expected = sorted(filewalk.walk_unique_files([sandbox_home]))
        assert expected

        monkeypatch.setenv(native_walk.HELPER_ENV, str(_fake_helper(tmp_path, body)))
        with pytest.warns(RuntimeWarning, match="falling back to the Python walker"):
            assert sorted(filewalk.walk_unique_files([sandbox_home])) == expected


# --------------------------------------------------------------------------
# The real helper against the reference implementation
# --------------------------------------------------------------------------


def _built_helper() -> Path | None:
    configured = os.environ.get(native_walk.HELPER_ENV)
    candidates = [
        Path(configured) if configured and configured.lower() not in native_walk._DISABLED else None,
        native_walk._BUNDLED_HELPER,
        _REPO / "native" / "fclean-walk" / "target" / "release" / "fclean-walk",
    ]
    for candidate in candidates:
        if candidate is not None and candidate.is_file() and os.access(candidate, os.X_OK):
            return candidate
    return None


_HELPER = _built_helper()
needs_helper = pytest.mark.skipif(_HELPER is None, reason="fclean-walk is not built (cargo build --release)")


@needs_helper
class TestAgainstThePythonWalker:
    def test_same_candidates_sizes_and_times(self, sandbox_config, sandbox_home, monkeypatch):
        _tree(sandbox_home)
        monkeypatch.setenv(native_walk.HELPER_ENV, "0")
        reference = _scan(sandbox_config, sandbox_home)
        monkeypatch.setenv(native_walk.HELPER_ENV, str(_HELPER))
        with warnings.catch_warnings():
            warnings.simplefilter("error")  # a silent fallback would make this test vacuous
            native = _scan(sandbox_config, sandbox_home)

        assert _summary(native) == _summary(reference)
        assert {str(c.path) for c in native.candidates} == {
            str(sandbox_home / "projects" / "app" / "junk"),
            str(sandbox_home / "projects" / "app" / "build.log"),
            str(sandbox_home / "top" / "one.tmp"),
            str(sandbox_home / "café [1]" / "unicode name.log"),
        }
        times = {str(c.path): c.mtime for c in reference.candidates}
        assert all(abs(c.mtime - times[str(c.path)]) < 1e-3 for c in native.candidates)
        junk = next(c for c in native.candidates if c.is_dir)
        assert junk.size_bytes == 1000  # 300 + 700, summed through getattrlistbulk

    def test_unreadable_directories_are_reported_the_same_way(self, sandbox_config, sandbox_home, monkeypatch):
        _tree(sandbox_home)
        locked = sandbox_home / "projects" / "locked"
        locked.mkdir()
        locked.chmod(0)
        try:
            monkeypatch.setenv(native_walk.HELPER_ENV, "0")
            reference = _scan(sandbox_config, sandbox_home)
            monkeypatch.setenv(native_walk.HELPER_ENV, str(_HELPER))
            native = _scan(sandbox_config, sandbox_home)
        finally:
            locked.chmod(0o700)

        assert sorted(native.errors) == sorted(reference.errors)
        assert any("Permission denied" in e for e in native.errors)

    def test_comparison_key_matches_safety_key(self):
        """The helper prunes with the same canonical key the deny-list uses.
        (Pruning only — Python re-checks every reported path regardless.)"""
        table = json.loads((Path(__file__).parent / "safety_cases.json").read_text())
        strings = sorted({c["path"] for c in table["cases"]} | {"Straße", "İstanbul", "ǅ", "ﬃ"})

        out = subprocess.run(
            [str(_HELPER), "key"], input=json.dumps(strings), capture_output=True, text=True, check=True
        )

        assert json.loads(out.stdout) == [safety._key(s) for s in strings]

    def test_rejects_a_request_it_cannot_honour(self):
        request = {"deny_home": "", "deny_prefixes": [], "walks": [{"base": "/", "pattern": "*", "kind": "socket"}]}
        out = subprocess.run([str(_HELPER)], input=json.dumps(request), capture_output=True, text=True)
        assert out.returncode != 0
        assert "unknown kind" in out.stderr


    def test_file_walk_matches_the_python_walk(self, sandbox_config, sandbox_home, tmp_path, monkeypatch):
        """Every way one file can be reached twice, plus the things that are
        not files to compare — against the Python walk, by physical identity
        (which of a hard link's names is reported is unspecified)."""
        _tree(sandbox_home)
        app = sandbox_home / "projects" / "app"
        os.link(app / "build.log", app / "build-hardlink.log")
        os.mkfifo(app / "a-fifo")
        (sandbox_home / "alias-of-projects").symlink_to(sandbox_home / "projects")
        roots = [sandbox_home, sandbox_home / "projects", sandbox_home / "alias-of-projects"]
        if (sandbox_home / "PROJECTS").exists():  # case-insensitive filesystem
            roots.append(sandbox_home / "PROJECTS")

        def walk(min_size):
            found = list(filewalk.walk_unique_files(roots, min_size=min_size))
            ids = [(os.lstat(p).st_dev, os.lstat(p).st_ino) for p, _ in found]
            assert len(ids) == len(set(ids)), "a physical file was reported twice"
            return {i: (st.st_size, round(st.st_mtime, 3)) for i, (_, st) in zip(ids, found, strict=True)}

        for min_size in (0, 11, 301):
            monkeypatch.setenv(native_walk.HELPER_ENV, "0")
            reference = walk(min_size)
            monkeypatch.setenv(native_walk.HELPER_ENV, str(_HELPER))
            with warnings.catch_warnings():
                warnings.simplefilter("error")  # a silent fallback would make this vacuous
                assert walk(min_size) == reference
        assert reference  # the >=301-byte pass still found junk/deep/b.bin
        monkeypatch.setenv(native_walk.HELPER_ENV, str(_HELPER))
        names = {p.name for p, _ in filewalk.walk_unique_files(roots)}
        assert "a-fifo" not in names and "debug.log" not in names and "mail.log" not in names

    def test_duplicates_and_large_files_agree_across_walkers(self, sandbox_config, sandbox_home, monkeypatch):
        _tree(sandbox_home)
        (sandbox_home / "copy-of-a.bin").write_bytes(b"x" * 300)  # a genuine duplicate of junk/a.bin
        results = {}
        for label, env in (("python", "0"), ("native", str(_HELPER))):
            monkeypatch.setenv(native_walk.HELPER_ENV, env)
            groups = duplicates.find_duplicates([sandbox_home], sandbox_config, min_size_bytes=100)
            large = largefiles.find_large_files([sandbox_home], sandbox_config, top=5, min_size_bytes=100)
            results[label] = ([(g.sha256, g.size_bytes, g.paths) for g in groups], [(f.path, f.size_bytes) for f in large])

        assert results["native"] == results["python"]
        assert [len(paths) for _, _, paths in results["native"][0]] == [2]
