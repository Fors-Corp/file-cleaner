import json
import os
import types
from pathlib import Path

import pytest
from typer.testing import CliRunner

from filecleaner import cli as cli_mod
from filecleaner import duplicates, models

runner = CliRunner()


def test_finds_identical_files(tmp_path, sandbox_config):
    content = b"x" * 5000
    a = tmp_path / "a.bin"
    b = tmp_path / "sub" / "b.bin"
    b.parent.mkdir()
    c = tmp_path / "c.bin"
    a.write_bytes(content)
    b.write_bytes(content)
    c.write_bytes(b"y" * 5000)

    groups = duplicates.find_duplicates([tmp_path], sandbox_config, min_size_bytes=10)

    assert len(groups) == 1
    group = groups[0]
    assert group.size_bytes == 5000
    assert set(group.paths) == {a, b}
    assert group.wasted_bytes == 5000


def test_respects_min_size(tmp_path, sandbox_config):
    content = b"x" * 100
    (tmp_path / "a.bin").write_bytes(content)
    (tmp_path / "b.bin").write_bytes(content)

    groups = duplicates.find_duplicates([tmp_path], sandbox_config, min_size_bytes=1000)

    assert groups == []


def test_no_duplicates_for_unique_files(tmp_path, sandbox_config):
    (tmp_path / "a.bin").write_bytes(b"a" * 5000)
    (tmp_path / "b.bin").write_bytes(b"b" * 5000)

    groups = duplicates.find_duplicates([tmp_path], sandbox_config, min_size_bytes=10)

    assert groups == []


def test_two_same_size_duplicate_pairs_stay_separate_groups(tmp_path, sandbox_config):
    """Full-hash results are now merged by size alone (see find_duplicates'
    docstring comment) since equal content implies equal partial hash — but
    two *different*-content duplicate pairs sharing a size must still land
    in two separate groups, not get merged into one."""
    (tmp_path / "a1.bin").write_bytes(b"a" * 5000)
    (tmp_path / "a2.bin").write_bytes(b"a" * 5000)
    (tmp_path / "b1.bin").write_bytes(b"b" * 5000)
    (tmp_path / "b2.bin").write_bytes(b"b" * 5000)

    groups = duplicates.find_duplicates([tmp_path], sandbox_config, min_size_bytes=10)

    assert len(groups) == 2
    path_sets = {frozenset(g.paths) for g in groups}
    assert path_sets == {
        frozenset({tmp_path / "a1.bin", tmp_path / "a2.bin"}),
        frozenset({tmp_path / "b1.bin", tmp_path / "b2.bin"}),
    }


def test_one_file_reached_twice_is_not_a_duplicate(one_file_reached_twice, sandbox_config):
    """A file is only a duplicate of a DIFFERENT file. The same physical file
    arriving under two spellings hashes identical to itself, and --apply
    would then purge the only copy."""
    roots, _real = one_file_reached_twice

    assert duplicates.find_duplicates(roots, sandbox_config, min_size_bytes=10) == []


def test_real_duplicate_is_reported_once_despite_aliasing(one_file_reached_twice, sandbox_config):
    roots, real = one_file_reached_twice
    copy = real.parent / "copy.bin"
    copy.write_bytes(real.read_bytes())

    groups = duplicates.find_duplicates(roots, sandbox_config, min_size_bytes=10)

    assert len(groups) == 1
    # Two physical files, however many names or routes lead to them — so
    # exactly one copy's worth of space is reclaimable, not three.
    assert len(groups[0].paths) == 2
    assert copy.name in {p.name for p in groups[0].paths}
    assert groups[0].wasted_bytes == real.stat().st_size


def test_apply_never_deletes_the_only_copy(one_file_reached_twice):
    roots, real = one_file_reached_twice
    content = real.read_bytes()

    result = runner.invoke(
        cli_mod.app, ["duplicates", *map(str, roots), "--min-size", "10", "--apply", "--yes", "--json"]
    )

    assert result.exit_code == 0, result.output
    assert json.loads(result.stdout)["deleted"] == 0
    assert real.read_bytes() == content


def test_apply_refuses_a_group_that_is_one_file_twice(sandbox_home, monkeypatch):
    """Defence in depth: even if the finder ever handed over one file under
    two spellings again, the apply path must not delete it."""
    top = sandbox_home / "Stuff"
    top.mkdir()
    real = top / "only.bin"
    real.write_bytes(b"only copy " * 500)
    link = sandbox_home / "link"
    link.symlink_to(top, target_is_directory=True)
    group = models.DuplicateGroup(sha256="abc", size_bytes=5000, paths=[real, link / "only.bin"])
    monkeypatch.setattr(duplicates, "find_duplicates", lambda *_args, **_kwargs: [group])

    result = runner.invoke(
        cli_mod.app, ["duplicates", str(top), str(link), "--min-size", "10", "--apply", "--yes", "--json"]
    )

    assert result.exit_code == 0, result.output
    payload = json.loads(result.stdout)
    assert payload["deleted"] == 0
    assert [s["path"] for s in payload["skipped"]] == [str(link / "only.bin")]
    assert "same file" in payload["skipped"][0]["reason"]
    assert real.exists()


class TestSelectDeletions:
    def test_refuses_a_path_that_is_the_kept_file(self, tmp_path):
        real = tmp_path / "real.bin"
        real.write_bytes(b"x" * 10)
        hard = tmp_path / "hard.bin"
        os.link(real, hard)
        copy = tmp_path / "copy.bin"
        copy.write_bytes(b"x" * 10)
        os.utime(real, (1000, 1000))  # shared inode: also sets hard.bin's mtime
        os.utime(copy, (2000, 2000))
        group = models.DuplicateGroup(sha256="abc", size_bytes=10, paths=[copy, hard, real])

        to_delete, refused = duplicates.select_deletions([group], keep="oldest")

        assert to_delete == [copy]
        assert len(refused) == 1
        assert "same file" in refused[0].reason

    def test_refuses_the_whole_group_when_the_kept_file_is_gone(self, tmp_path):
        """shortest-path needs no stat to pick a keeper, so it could pick one
        that vanished since the scan — and then delete the last real copy."""
        gone = tmp_path / "a.bin"
        survivor = tmp_path / "a_much_longer_name.bin"
        survivor.write_bytes(b"x" * 10)
        group = models.DuplicateGroup(sha256="abc", size_bytes=10, paths=[gone, survivor])

        to_delete, refused = duplicates.select_deletions([group], keep="shortest-path")

        assert to_delete == []
        assert [s.path for s in refused] == [str(survivor)]

    def test_keep_oldest_deletes_the_rest(self, tmp_path):
        older = tmp_path / "older.bin"
        newer = tmp_path / "newer.bin"
        older.write_bytes(b"x" * 10)
        newer.write_bytes(b"x" * 10)
        os.utime(older, (1000, 1000))
        os.utime(newer, (2000, 2000))
        group = models.DuplicateGroup(sha256="abc", size_bytes=10, paths=[older, newer])

        to_delete, refused = duplicates.select_deletions([group], keep="oldest")

        assert to_delete == [newer]
        assert refused == []

    def test_keep_newest_deletes_the_rest(self, tmp_path):
        older = tmp_path / "older.bin"
        newer = tmp_path / "newer.bin"
        older.write_bytes(b"x" * 10)
        newer.write_bytes(b"x" * 10)
        os.utime(older, (1000, 1000))
        os.utime(newer, (2000, 2000))
        group = models.DuplicateGroup(sha256="abc", size_bytes=10, paths=[older, newer])

        to_delete, refused = duplicates.select_deletions([group], keep="newest")

        assert to_delete == [older]
        assert refused == []

    def test_keep_shortest_path(self, tmp_path):
        short = tmp_path / "a.bin"
        long = tmp_path / "a_much_longer_name.bin"
        short.write_bytes(b"x" * 10)
        long.write_bytes(b"x" * 10)
        group = models.DuplicateGroup(sha256="abc", size_bytes=10, paths=[short, long])

        to_delete, refused = duplicates.select_deletions([group], keep="shortest-path")

        assert to_delete == [long]
        assert refused == []

    def test_unknown_strategy_raises(self, tmp_path):
        group = models.DuplicateGroup(sha256="abc", size_bytes=10, paths=[tmp_path / "a"])
        with pytest.raises(ValueError, match="unknown keep strategy"):
            duplicates.select_deletions([group], keep="bogus")

    def test_multiple_groups_each_keep_one(self, tmp_path):
        paths1 = [tmp_path / "g1_a.bin", tmp_path / "g1_b.bin"]
        paths2 = [tmp_path / "g2_a.bin", tmp_path / "g2_b.bin", tmp_path / "g2_c.bin"]
        for p in paths1 + paths2:
            p.write_bytes(b"x")
        groups = [
            models.DuplicateGroup(sha256="a", size_bytes=1, paths=paths1),
            models.DuplicateGroup(sha256="b", size_bytes=1, paths=paths2),
        ]
        to_delete, refused = duplicates.select_deletions(groups, keep="oldest")
        assert len(to_delete) == 3  # one kept per group: (2-1) + (3-1)
        assert refused == []


def test_a_file_evicted_to_icloud_is_never_read(tmp_path, sandbox_config, monkeypatch):
    """macOS keeps only a placeholder for a file it has evicted to iCloud
    (``SF_DATALESS``) and downloads the contents the moment anything reads it.
    Hashing a home directory's worth blocked for hours and filled the disk this
    tool exists to free — and a file with no contents here wastes no space here,
    so it is not a duplicate worth finding."""
    monkeypatch.setenv("FCLEAN_NATIVE_WALK", "0")
    for name in ("here.bin", "also-here.bin", "evicted.bin", "evicted-too.bin"):
        (tmp_path / name).write_bytes(b"same " * 2000)
    real_lstat, opened = os.lstat, []

    def lstat(path, *args, **kwargs):
        st = real_lstat(path, *args, **kwargs)
        if "evicted" in os.path.basename(os.fspath(path)):  # not the folder: pytest names that after the test
            fields = {name: getattr(st, name) for name in dir(st) if name.startswith("st_")}
            return types.SimpleNamespace(**{**fields, "st_flags": st.st_flags | duplicates.SF_DATALESS})
        return st

    real_open = Path.open

    def spying_open(self, *args, **kwargs):
        opened.append(self.name)
        return real_open(self, *args, **kwargs)

    monkeypatch.setattr(duplicates.os, "lstat", lstat)
    monkeypatch.setattr(Path, "open", spying_open)

    groups = duplicates.find_duplicates([tmp_path], sandbox_config)

    assert [sorted(p.name for p in g.paths) for g in groups] == [["also-here.bin", "here.bin"]]
    assert not [name for name in opened if "evicted" in name]
