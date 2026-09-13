import os

import pytest

from filecleaner import duplicates, models


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


class TestSelectDeletions:
    def test_keep_oldest_deletes_the_rest(self, tmp_path):
        older = tmp_path / "older.bin"
        newer = tmp_path / "newer.bin"
        older.write_bytes(b"x" * 10)
        newer.write_bytes(b"x" * 10)
        os.utime(older, (1000, 1000))
        os.utime(newer, (2000, 2000))
        group = models.DuplicateGroup(sha256="abc", size_bytes=10, paths=[older, newer])

        to_delete = duplicates.select_deletions([group], keep="oldest")

        assert to_delete == [newer]

    def test_keep_newest_deletes_the_rest(self, tmp_path):
        older = tmp_path / "older.bin"
        newer = tmp_path / "newer.bin"
        older.write_bytes(b"x" * 10)
        newer.write_bytes(b"x" * 10)
        os.utime(older, (1000, 1000))
        os.utime(newer, (2000, 2000))
        group = models.DuplicateGroup(sha256="abc", size_bytes=10, paths=[older, newer])

        to_delete = duplicates.select_deletions([group], keep="newest")

        assert to_delete == [older]

    def test_keep_shortest_path(self, tmp_path):
        short = tmp_path / "a.bin"
        long = tmp_path / "a_much_longer_name.bin"
        short.write_bytes(b"x" * 10)
        long.write_bytes(b"x" * 10)
        group = models.DuplicateGroup(sha256="abc", size_bytes=10, paths=[short, long])

        to_delete = duplicates.select_deletions([group], keep="shortest-path")

        assert to_delete == [long]

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
        to_delete = duplicates.select_deletions(groups, keep="oldest")
        assert len(to_delete) == 3  # one kept per group: (2-1) + (3-1)
