from filecleaner import scanner


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
