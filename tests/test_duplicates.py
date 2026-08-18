from filecleaner import duplicates


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
