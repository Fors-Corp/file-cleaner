import pytest

from filecleaner import scanner
from filecleaner.models import Candidate, Rule


def test_scan_finds_old_cache(sandbox_config, sandbox_home, age_path):
    cache_dir = sandbox_home / "Library" / "Caches" / "SomeApp"
    cache_dir.mkdir(parents=True)
    (cache_dir / "data.bin").write_bytes(b"x" * 1000)
    age_path(cache_dir, days=10)
    age_path(cache_dir / "data.bin", days=10)

    result = scanner.run_scan(sandbox_config, only_rules={"system_caches"})

    matched = [c for c in result.candidates if c.path == cache_dir]
    assert len(matched) == 1
    assert matched[0].size_bytes == 1000
    assert matched[0].category == "Caches"


def test_scan_ignores_recent_cache(sandbox_config, sandbox_home):
    cache_dir = sandbox_home / "Library" / "Caches" / "FreshApp"
    cache_dir.mkdir(parents=True)
    (cache_dir / "data.bin").write_bytes(b"x" * 1000)
    # left at current mtime — younger than the rule's min_age_days

    result = scanner.run_scan(sandbox_config, only_rules={"system_caches"})

    assert not any(c.path == cache_dir for c in result.candidates)


def test_scan_respects_deny_list_even_when_rule_matches(sandbox_config, sandbox_home, age_path):
    cache_dir = sandbox_home / "Library" / "Caches" / "ProtectedApp"
    cache_dir.mkdir(parents=True)
    (cache_dir / "data.bin").write_bytes(b"x" * 1000)
    age_path(cache_dir, days=10)
    age_path(cache_dir / "data.bin", days=10)

    sandbox_config["protected_paths"] = [str(cache_dir)]

    result = scanner.run_scan(sandbox_config, only_rules={"system_caches"})

    assert not any(c.path == cache_dir for c in result.candidates)


def test_scan_skips_symlinks(sandbox_config, sandbox_home):
    real_dir = sandbox_home / "real_cache"
    real_dir.mkdir()
    caches = sandbox_home / "Library" / "Caches"
    caches.mkdir(parents=True)
    link = caches / "LinkedApp"
    link.symlink_to(real_dir)

    result = scanner.run_scan(sandbox_config, only_rules={"system_caches"})

    assert not any(c.path == link for c in result.candidates)


def test_disabled_rule_excluded_by_default(sandbox_config, sandbox_home, age_path):
    node_modules = sandbox_home / "project" / "node_modules"
    node_modules.mkdir(parents=True)
    (node_modules / "pkg.js").write_text("x")
    age_path(node_modules, days=60)

    result = scanner.run_scan(sandbox_config)  # no only_rules -> respects enabled_by_default

    assert not any(c.rule_id == "dev_node_modules" for c in result.candidates)


def test_unknown_rule_id_raises(sandbox_config, sandbox_home):
    with pytest.raises(scanner.UnknownRuleError):
        scanner.run_scan(sandbox_config, only_rules={"totally_made_up_rule"})


def test_include_disabled_reports_opt_in_rules(sandbox_config, sandbox_home, age_path):
    node_modules = sandbox_home / "project" / "node_modules"
    node_modules.mkdir(parents=True)
    pkg = node_modules / "pkg.js"
    pkg.write_text("x")
    age_path(pkg, days=60)
    age_path(node_modules, days=60)

    result = scanner.run_scan(sandbox_config, include_disabled=True)

    assert any(c.rule_id == "dev_node_modules" for c in result.candidates)


class TestGlobMatcher:
    def test_double_star_matches_any_depth(self):
        matcher = scanner.GlobMatcher.compile("**/.DS_Store")
        assert matcher.matches(".DS_Store")
        assert matcher.matches("a/b/c/.DS_Store")
        assert not matcher.matches("a/b/c/NotIt")

    def test_single_star_does_not_cross_slash(self):
        matcher = scanner.GlobMatcher.compile("Library/Caches/*")
        assert matcher.matches("Library/Caches/App")
        assert not matcher.matches("Library/Caches/App/nested")

    def test_static_prefix_is_the_non_wildcard_lead(self):
        matcher = scanner.GlobMatcher.compile("Library/Caches/*")
        assert matcher.static_prefix == "Library/Caches"

    def test_trailing_double_star_exclude_matches_directory_itself(self):
        matcher = scanner.GlobMatcher.compile("Library/**")
        assert matcher.matches("Library")
        assert matcher.matches("Library/Anything/Deep")


def test_exclude_prunes_entire_subtree(sandbox_config, sandbox_home):
    # ds_store excludes Library/** — a .DS_Store *inside* Library must never match,
    # even though the pattern **/.DS_Store would otherwise reach it.
    lib_ds = sandbox_home / "Library" / "SomeFolder" / ".DS_Store"
    lib_ds.parent.mkdir(parents=True)
    lib_ds.write_bytes(b"x")
    home_ds = sandbox_home / "Documents" / ".DS_Store"
    home_ds.parent.mkdir(parents=True)
    home_ds.write_bytes(b"x")

    result = scanner.run_scan(sandbox_config, only_rules={"ds_store"})

    matched_paths = {c.path for c in result.candidates}
    assert home_ds in matched_paths
    assert lib_ds not in matched_paths


def test_directory_age_uses_newest_file_inside(sandbox_config, sandbox_home, age_path):
    """A cache directory with one freshly-written file inside must not be
    treated as stale just because the directory's own mtime is old."""
    cache_dir = sandbox_home / "Library" / "Caches" / "ActiveApp"
    cache_dir.mkdir(parents=True)
    old_file = cache_dir / "old.bin"
    old_file.write_bytes(b"x" * 100)
    age_path(cache_dir, days=10)
    age_path(old_file, days=10)

    new_file = cache_dir / "fresh.bin"
    new_file.write_bytes(b"y" * 100)  # written just now, dir mtime bumped too

    result = scanner.run_scan(sandbox_config, only_rules={"system_caches"})

    assert not any(c.path == cache_dir for c in result.candidates)


def test_coalesce_drops_nested_candidate():
    parent = Candidate(path=__import__("pathlib").Path("/a/b"), size_bytes=100, is_dir=True, mtime=0, rule_id="r1", category="C", risk="low")
    child = Candidate(path=__import__("pathlib").Path("/a/b/c"), size_bytes=10, is_dir=False, mtime=0, rule_id="r2", category="C", risk="low")
    kept, dropped = scanner.coalesce([parent, child])
    assert kept == [parent]
    assert dropped == 1


def test_coalesce_drops_exact_duplicate():
    from pathlib import Path

    a = Candidate(path=Path("/a/b"), size_bytes=100, is_dir=True, mtime=0, rule_id="r1", category="C", risk="low")
    b = Candidate(path=Path("/a/b"), size_bytes=100, is_dir=True, mtime=0, rule_id="r2", category="C", risk="low")
    kept, dropped = scanner.coalesce([a, b])
    assert len(kept) == 1
    assert dropped == 1


def test_select_rules_only_rules_ignores_enabled_state(sandbox_config):
    # old_downloads is disabled by default; --rules should still select it explicitly.
    selected = scanner.select_rules(sandbox_config, only_rules={"old_downloads"})
    assert [r.id for r in selected] == ["old_downloads"]


def test_scan_result_duration_is_recorded(sandbox_config, sandbox_home):
    result = scanner.run_scan(sandbox_config, only_rules={"system_caches"})
    assert result.duration_seconds >= 0.0


def _candidate_key(c):
    return (str(c.path), c.size_bytes, c.rule_id)


@pytest.mark.parametrize("concurrency", [1, 8])
def test_run_scan_same_results_regardless_of_concurrency(sandbox_config, sandbox_home, age_path, concurrency):
    """(rule, root) walks now run in a thread pool — results must be
    identical to a sequential run, just potentially faster."""
    for i in range(5):
        cache_dir = sandbox_home / "Library" / "Caches" / f"App{i}"
        cache_dir.mkdir(parents=True)
        (cache_dir / "data.bin").write_bytes(b"x" * (1000 + i))
        age_path(cache_dir, days=10)
        age_path(cache_dir / "data.bin", days=10)

    sandbox_config["scan_concurrency"] = concurrency
    result = scanner.run_scan(sandbox_config)
    baseline_config = dict(sandbox_config, scan_concurrency=1)
    baseline = scanner.run_scan(baseline_config)

    assert sorted(map(_candidate_key, result.candidates)) == sorted(map(_candidate_key, baseline.candidates))


def test_run_scan_errors_capped_across_concurrent_tasks(sandbox_config, sandbox_home, monkeypatch):
    """The global error cap must hold even though errors are now collected
    from multiple concurrently-running (rule, root) tasks."""
    import os

    real_scandir = os.scandir

    def flaky_scandir(path):
        if "blocked" in str(path):
            raise PermissionError("nope")
        return real_scandir(path)

    rules = tuple(
        Rule(
            id=f"unreadable_probe_{i}",
            label="probe",
            category="Test",
            description="",
            enabled_by_default=True,
            risk="low",
            kind="dir",
            scope="home",
            include_globs=(f"blocked{i}/*",),
        )
        for i in range(3)
    )
    for i in range(3):
        d = sandbox_home / f"blocked{i}"
        d.mkdir()
        (d / "sub").mkdir()

    monkeypatch.setattr(scanner.os, "scandir", flaky_scandir)
    monkeypatch.setattr(scanner, "_MAX_ERRORS", 2)
    sandbox_config["scan_concurrency"] = 4

    result = scanner.run_scan(sandbox_config, rules=rules, include_disabled=True)
    assert len(result.errors) <= 2


def test_scan_caps_reported_errors(sandbox_config, sandbox_home, monkeypatch):
    """A rule that hits many unreadable directories should never grow the
    error list without bound."""
    rule = Rule(
        id="unreadable_probe",
        label="probe",
        category="Test",
        description="",
        enabled_by_default=True,
        risk="low",
        kind="dir",
        scope="home",
        include_globs=("blocked/*",),
    )
    blocked = sandbox_home / "blocked"
    blocked.mkdir()
    for i in range(5):
        (blocked / f"sub{i}").mkdir()
        (blocked / f"sub{i}" / "inner").mkdir()

    import os

    real_scandir = os.scandir

    def flaky_scandir(path):
        if "sub" in str(path) and "inner" not in str(path):
            raise PermissionError("nope")
        return real_scandir(path)

    monkeypatch.setattr(scanner.os, "scandir", flaky_scandir)
    monkeypatch.setattr(scanner, "_MAX_ERRORS", 2)

    from filecleaner.models import ScanResult

    result = ScanResult(scan_roots=[sandbox_home])
    scanner.scan_rule(sandbox_home, rule, result, extra_protected=())
    assert len(result.errors) <= 2


class TestRootScoping:
    """`run_scan`/`count_total_dirs` default their root to the current
    working directory (not the home directory) — see `sandbox_home`'s
    `monkeypatch.chdir`, which is why every other test in this module still
    gets the traditional "scan home" behavior without passing `root`."""

    def test_defaults_to_cwd_not_home(self, tmp_path, sandbox_config, monkeypatch):
        workdir = tmp_path / "somewhere"
        workdir.mkdir()
        monkeypatch.chdir(workdir)
        sandbox_config["rules"] = [{"id": "logfiles", "include": ["*.log"], "min_age_days": 0}]
        (workdir / "old.log").write_bytes(b"x" * 10)

        result = scanner.run_scan(sandbox_config, only_rules={"logfiles"}, include_disabled=True)

        assert result.scan_roots == [workdir.resolve()]
        assert any(c.path == workdir / "old.log" for c in result.candidates)

    def test_explicit_root_overrides_cwd(self, tmp_path, sandbox_config, sandbox_home):
        other = tmp_path / "other"
        other.mkdir()
        sandbox_config["rules"] = [{"id": "logfiles", "include": ["*.log"], "min_age_days": 0}]
        (other / "old.log").write_bytes(b"x" * 10)
        # cwd is sandbox_home (chdir'd by the fixture); explicit root wins.
        result = scanner.run_scan(sandbox_config, only_rules={"logfiles"}, include_disabled=True, root=other)

        assert result.scan_roots == [other.resolve()]
        assert any(c.path == other / "old.log" for c in result.candidates)

    def test_scoped_root_excludes_each_volume_rules(self, tmp_path, sandbox_config):
        scoped = tmp_path / "scoped"
        scoped.mkdir()
        _root, roots, root_in_roots, volume_roots, _extra = scanner._scan_setup(sandbox_config, root=scoped)
        assert roots == [scoped.resolve()]
        assert root_in_roots is True
        assert volume_roots == []

    def test_home_root_restores_whole_machine_roots(self, sandbox_config, sandbox_home):
        effective_root, _roots, root_in_roots, _volume_roots, _extra = scanner._scan_setup(
            sandbox_config, root=sandbox_home
        )
        assert effective_root == sandbox_home.resolve()
        assert root_in_roots is True

    def test_count_total_dirs_respects_root(self, tmp_path, sandbox_config):
        scoped = tmp_path / "scoped"
        sub = scoped / "sub"
        sub.mkdir(parents=True)
        sandbox_config["rules"] = [{"id": "logfiles", "include": ["**/*.log"], "min_age_days": 0}]
        (sub / "old.log").write_bytes(b"x" * 10)

        total = scanner.count_total_dirs(sandbox_config, only_rules={"logfiles"}, include_disabled=True, root=scoped)
        assert total >= 1


class TestProtectedPathsDuringWalk:
    """The walk checks the deny-list per entry without touching the
    filesystem (`safety.is_protected_resolved`), which is only sound because
    the start directory is resolved first. These pin the cases where the
    path as typed and the path on disk disagree."""

    @staticmethod
    def _mail(home):
        mail = home / "Library" / "Mail" / "V10"
        mail.mkdir(parents=True)
        (mail / "msg.emlx").write_bytes(b"x" * 10)
        logs = home / "Library" / "Logs"
        logs.mkdir(parents=True)
        (logs / "app.emlx").write_bytes(b"x" * 10)
        return mail / "msg.emlx", logs / "app.emlx"

    @staticmethod
    def _needs_case_insensitive_fs(home):
        if not (home / "LIBRARY").exists():
            pytest.skip("needs a case-insensitive filesystem")

    def test_custom_rule_prefix_spelled_in_the_wrong_case(self, sandbox_config, sandbox_home):
        self._mail(sandbox_home)
        self._needs_case_insensitive_fs(sandbox_home)
        sandbox_config["rules"] = [{"id": "sneaky", "include": ["library/mail/**/*.emlx"], "min_age_days": 0}]

        result = scanner.run_scan(sandbox_config, only_rules={"sneaky"}, include_disabled=True)

        assert result.candidates == []

    def test_wrong_case_prefix_above_a_protected_directory(self, sandbox_config, sandbox_home):
        _protected, ordinary = self._mail(sandbox_home)
        self._needs_case_insensitive_fs(sandbox_home)
        sandbox_config["rules"] = [{"id": "sneaky", "include": ["library/**/*.emlx"], "min_age_days": 0}]

        result = scanner.run_scan(sandbox_config, only_rules={"sneaky"}, include_disabled=True)

        # The walk ran (the ordinary file is found, reported as the rule spelled it) ...
        assert [c.path for c in result.candidates] == [sandbox_home / "library" / "Logs" / ordinary.name]
        # ... but never entered ~/Library/Mail.

    def test_prefix_through_a_symlinked_ancestor(self, tmp_path, sandbox_config, sandbox_home):
        self._mail(sandbox_home)
        box = tmp_path / "box"
        box.mkdir()
        (box / "alias").symlink_to(sandbox_home)
        sandbox_config["rules"] = [{"id": "sneaky", "include": ["alias/Library/**/*.emlx"], "min_age_days": 0}]

        result = scanner.run_scan(sandbox_config, only_rules={"sneaky"}, include_disabled=True, root=box)

        # Reported as typed (through the alias); ~/Library/Mail is recognised
        # through the alias and skipped.
        assert [c.path for c in result.candidates] == [box / "alias" / "Library" / "Logs" / "app.emlx"]
