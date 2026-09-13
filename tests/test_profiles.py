import pytest

from filecleaner import config as config_mod
from filecleaner import profiles as profiles_mod


def test_list_profiles_empty_initially(sandbox_home):
    assert profiles_mod.list_profiles() == []


def test_save_and_list_profile(sandbox_config):
    sandbox_config["retention_days"] = 7
    profiles_mod.save_profile("quick", sandbox_config)
    assert profiles_mod.list_profiles() == ["quick"]


def test_save_only_tracks_profile_keys(sandbox_config):
    sandbox_config["retention_days"] = 7
    sandbox_config["quarantine_dir"] = "/should/not/be/saved"
    profiles_mod.save_profile("quick", sandbox_config)
    loaded = profiles_mod.load_profile("quick")
    assert loaded["retention_days"] == 7
    assert "quarantine_dir" not in loaded


def test_load_missing_profile_raises(sandbox_home):
    with pytest.raises(profiles_mod.ProfileError):
        profiles_mod.load_profile("does-not-exist")


def test_delete_profile(sandbox_config):
    profiles_mod.save_profile("temp", sandbox_config)
    assert profiles_mod.delete_profile("temp") is True
    assert profiles_mod.delete_profile("temp") is False
    assert profiles_mod.list_profiles() == []


def test_apply_profile_layers_onto_config_without_mutating_input(sandbox_config):
    sandbox_config["retention_days"] = 99
    profiles_mod.save_profile("deep", sandbox_config)

    base = config_mod.default_config()
    merged = profiles_mod.apply_profile(base, "deep")

    assert merged["retention_days"] == 99
    assert base["retention_days"] == 30  # unchanged
    # Keys the profile doesn't track still come from the base config.
    assert merged["quarantine_dir"] == base["quarantine_dir"]


@pytest.mark.parametrize("bad_name", ["", "has spaces", "../escape", "a" * 65])
def test_invalid_profile_names_rejected(sandbox_home, bad_name):
    with pytest.raises(profiles_mod.ProfileError):
        profiles_mod.save_profile(bad_name, config_mod.default_config())
