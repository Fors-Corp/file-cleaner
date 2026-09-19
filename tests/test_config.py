from pathlib import Path

import pytest

from filecleaner import config as config_mod


def test_default_config_matches_schema():
    cfg = config_mod.default_config()
    assert set(cfg.keys()) == set(config_mod.CONFIG_SCHEMA.keys())


def test_load_config_creates_file_on_first_run(sandbox_home):
    assert not config_mod.CONFIG_FILE.exists()
    cfg = config_mod.load_config()
    assert config_mod.CONFIG_FILE.exists()
    assert cfg["retention_days"] == 30
    # 0600 permissions: owner read/write only.
    assert (config_mod.CONFIG_FILE.stat().st_mode & 0o777) == 0o600


def test_load_config_merges_partial_file(sandbox_home):
    config_mod.ensure_dirs()
    config_mod.CONFIG_FILE.write_text('retention_days = 7\n')
    cfg = config_mod.load_config()
    assert cfg["retention_days"] == 7
    assert cfg["hash_duplicates_max_bytes"] == config_mod.default_config()["hash_duplicates_max_bytes"]


def test_load_config_reports_unknown_keys_as_warnings(sandbox_home):
    config_mod.ensure_dirs()
    config_mod.CONFIG_FILE.write_text('made_up_key = 1\n')
    warnings: list[str] = []
    config_mod.load_config(warnings=warnings)
    assert any("made_up_key" in w for w in warnings)


def test_load_config_raises_on_invalid_toml(sandbox_home):
    config_mod.ensure_dirs()
    config_mod.CONFIG_FILE.write_text("this is not [valid toml")
    with pytest.raises(config_mod.ConfigError):
        config_mod.load_config()


def test_load_config_raises_on_invalid_value_type(sandbox_home):
    config_mod.ensure_dirs()
    config_mod.CONFIG_FILE.write_text('retention_days = "not a number"\n')
    with pytest.raises(config_mod.ConfigError):
        config_mod.load_config()


def test_save_config_is_atomic_and_leaves_no_tmp_file(sandbox_home):
    cfg = config_mod.default_config()
    config_mod.save_config(cfg)
    leftovers = list(config_mod.CONFIG_DIR.glob(".config-*.toml"))
    assert leftovers == []
    assert config_mod.CONFIG_FILE.exists()


def test_extra_protected_paths_expands_user(sandbox_home):
    cfg = config_mod.default_config()
    cfg["protected_paths"] = ["~/keep-me"]
    paths = config_mod.extra_protected_paths(cfg)
    assert paths == (Path.home() / "keep-me",)


def test_add_and_remove_keep_path(sandbox_home):
    cfg = config_mod.default_config()
    config_mod.add_keep_path(cfg, "~/important")
    assert str(Path.home() / "important") in cfg["protected_paths"]
    # Adding twice does not duplicate.
    config_mod.add_keep_path(cfg, "~/important")
    assert cfg["protected_paths"].count(str(Path.home() / "important")) == 1

    assert config_mod.remove_keep_path(cfg, "~/important") is True
    assert config_mod.remove_keep_path(cfg, "~/important") is False


def test_data_paths_to_protect_includes_quarantine_dir(sandbox_home, tmp_path):
    cfg = config_mod.default_config()
    cfg["quarantine_dir"] = str(tmp_path / "custom-quarantine")
    protected = config_mod.data_paths_to_protect(cfg)
    assert Path(tmp_path / "custom-quarantine") in protected
    assert config_mod.CONFIG_DIR in protected
    assert config_mod.DATA_DIR in protected


class TestSetValue:
    def test_bool(self, sandbox_home):
        cfg = config_mod.default_config()
        config_mod.set_value(cfg, "volume_local_quarantine", "false")
        assert cfg["volume_local_quarantine"] is False
        config_mod.set_value(cfg, "volume_local_quarantine", "yes")
        assert cfg["volume_local_quarantine"] is True

    def test_int(self, sandbox_home):
        cfg = config_mod.default_config()
        config_mod.set_value(cfg, "retention_days", "14")
        assert cfg["retention_days"] == 14

    def test_int_rejects_garbage(self, sandbox_home):
        cfg = config_mod.default_config()
        with pytest.raises(config_mod.ConfigError):
            config_mod.set_value(cfg, "retention_days", "not-a-number")

    def test_negative_int_rejected(self, sandbox_home):
        cfg = config_mod.default_config()
        with pytest.raises(config_mod.ConfigError):
            config_mod.set_value(cfg, "retention_days", "-5")

    def test_unknown_key_rejected(self, sandbox_home):
        cfg = config_mod.default_config()
        with pytest.raises(config_mod.ConfigError):
            config_mod.set_value(cfg, "does_not_exist", "1")

    @pytest.mark.parametrize("key", ["rule_overrides", "rules", "rule_param_overrides"])
    def test_structured_keys_rejected(self, sandbox_home, key):
        cfg = config_mod.default_config()
        with pytest.raises(config_mod.ConfigError):
            config_mod.set_value(cfg, key, "system_caches=true")


class TestRuleParamOverrides:
    def test_valid_override_accepted(self, sandbox_home):
        cfg = config_mod.default_config()
        cfg["rule_param_overrides"] = {"system_caches": {"min_age_days": 14}}
        config_mod.validate_config(cfg)
        assert cfg["rule_param_overrides"]["system_caches"]["min_age_days"] == 14

    def test_unknown_field_rejected(self, sandbox_home):
        cfg = config_mod.default_config()
        cfg["rule_param_overrides"] = {"system_caches": {"bogus_field": 1}}
        with pytest.raises(config_mod.ConfigError):
            config_mod.validate_config(cfg)

    def test_negative_value_rejected(self, sandbox_home):
        cfg = config_mod.default_config()
        cfg["rule_param_overrides"] = {"system_caches": {"min_age_days": -1}}
        with pytest.raises(config_mod.ConfigError):
            config_mod.validate_config(cfg)

    def test_get_set_clear_round_trip(self, sandbox_home):
        cfg = config_mod.default_config()
        config_mod.set_rule_param_override(cfg, "system_caches", min_age_days=14)
        assert config_mod.get_rule_param_override(cfg, "system_caches") == {"min_age_days": 14}
        # Setting one field again leaves the other untouched.
        config_mod.set_rule_param_override(cfg, "system_caches", min_size_bytes=1024)
        assert config_mod.get_rule_param_override(cfg, "system_caches") == {
            "min_age_days": 14,
            "min_size_bytes": 1024,
        }
        assert config_mod.clear_rule_param_override(cfg, "system_caches") is True
        assert config_mod.clear_rule_param_override(cfg, "system_caches") is False


class TestScanConcurrency:
    def test_default_is_positive(self, sandbox_home):
        assert config_mod.default_config()["scan_concurrency"] >= 1

    def test_zero_rejected(self, sandbox_home):
        cfg = config_mod.default_config()
        cfg["scan_concurrency"] = 0
        with pytest.raises(config_mod.ConfigError):
            config_mod.validate_config(cfg)

    def test_settable_from_cli_value(self, sandbox_home):
        cfg = config_mod.default_config()
        config_mod.set_value(cfg, "scan_concurrency", "8")
        assert cfg["scan_concurrency"] == 8


def test_classifier_path_follows_the_data_dir(sandbox_home, tmp_path):
    """The classifier's weights live in the data dir *as it is now*, not
    where it pointed at import time. When this was a module-level constant,
    redirecting the data dir (as every test does) left it aimed at the real
    ``~/.filecleaner`` — so the suite trained the user's real classifier on
    fixture data, and failed outright on a machine with no such directory."""
    path = config_mod.get_classifier_path()

    assert path == config_mod.DATA_DIR / "classifier.json"
    assert path.is_relative_to(tmp_path)
    assert path.parent.is_dir()
