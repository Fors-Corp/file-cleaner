from filecleaner import largefiles


def test_finds_largest_files_in_order(tmp_path, sandbox_config):
    (tmp_path / "small.bin").write_bytes(b"x" * 10)
    (tmp_path / "medium.bin").write_bytes(b"x" * 100)
    (tmp_path / "big.bin").write_bytes(b"x" * 1000)

    results = largefiles.find_large_files([tmp_path], sandbox_config, top=2)

    assert [r.size_bytes for r in results] == [1000, 100]
    assert results[0].path.name == "big.bin"


def test_one_file_reached_twice_is_listed_once(one_file_reached_twice, sandbox_config):
    """Listing one physical file twice would double-count the space it uses."""
    roots, real = one_file_reached_twice

    results = largefiles.find_large_files(roots, sandbox_config, top=10)

    assert [r.size_bytes for r in results] == [real.stat().st_size]


def test_respects_min_size(tmp_path, sandbox_config):
    (tmp_path / "small.bin").write_bytes(b"x" * 10)
    (tmp_path / "big.bin").write_bytes(b"x" * 1000)

    results = largefiles.find_large_files([tmp_path], sandbox_config, top=10, min_size_bytes=500)

    assert len(results) == 1
    assert results[0].path.name == "big.bin"


def test_skips_symlinks(tmp_path, sandbox_config):
    real = tmp_path / "real.bin"
    real.write_bytes(b"x" * 1000)
    link = tmp_path / "link.bin"
    link.symlink_to(real)

    results = largefiles.find_large_files([tmp_path], sandbox_config, top=10)

    assert len(results) == 1
    assert results[0].path == real


def test_prunes_protected_directories(tmp_path, sandbox_config, sandbox_home):
    protected_dir = tmp_path / "important"
    protected_dir.mkdir()
    (protected_dir / "secret.bin").write_bytes(b"x" * 1000)
    sandbox_config["protected_paths"] = [str(protected_dir)]

    results = largefiles.find_large_files([tmp_path], sandbox_config, top=10)

    assert results == []


def test_empty_directory_returns_empty_list(tmp_path, sandbox_config):
    assert largefiles.find_large_files([tmp_path], sandbox_config, top=10) == []
