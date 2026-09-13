import pytest

from filecleaner import config as config_mod
from filecleaner.rules import (
    BUILTIN_RULES,
    RuleError,
    all_rules,
    apply_param_overrides,
    load_custom_rules,
    rules_by_id,
    unknown_override_ids,
    unknown_param_override_ids,
)


def test_rule_ids_are_unique():
    ids = [r.id for r in BUILTIN_RULES]
    assert len(ids) == len(set(ids))


def test_every_rule_has_include_globs():
    for rule in BUILTIN_RULES:
        assert rule.include_globs
        assert rule.scope in ("home", "root", "each_volume")
        assert rule.risk in ("low", "medium")


def test_rules_by_id_lookup():
    lookup = rules_by_id()
    assert "system_caches" in lookup
    assert lookup["system_caches"].category == "Caches"


def test_risky_categories_are_off_by_default():
    lookup = rules_by_id()
    assert lookup["dev_node_modules"].enabled_by_default is False
    assert lookup["old_downloads"].enabled_by_default is False


class TestCustomRules:
    def test_loads_a_valid_custom_rule(self):
        cfg = config_mod.default_config()
        cfg["rules"] = [{"id": "my_isos", "include": ["Downloads/*.iso"], "category": "Media"}]
        rules = load_custom_rules(cfg)
        assert len(rules) == 1
        assert rules[0].source == "custom"
        assert rules[0].category == "Media"
        assert rules[0].enabled_by_default is True  # defaults to enabled

    def test_all_rules_includes_custom_after_builtin(self):
        cfg = config_mod.default_config()
        cfg["rules"] = [{"id": "my_isos", "include": ["Downloads/*.iso"]}]
        combined = all_rules(cfg)
        assert len(combined) == len(BUILTIN_RULES) + 1
        assert combined[-1].id == "my_isos"

    def test_rejects_id_clashing_with_builtin(self):
        cfg = config_mod.default_config()
        cfg["rules"] = [{"id": "system_caches", "include": ["*"]}]
        with pytest.raises(RuleError, match="clashes"):
            load_custom_rules(cfg)

    def test_rejects_duplicate_custom_ids(self):
        cfg = config_mod.default_config()
        cfg["rules"] = [
            {"id": "dup", "include": ["*"]},
            {"id": "dup", "include": ["*"]},
        ]
        with pytest.raises(RuleError, match="duplicate"):
            load_custom_rules(cfg)

    def test_rejects_missing_include(self):
        cfg = config_mod.default_config()
        cfg["rules"] = [{"id": "no_include"}]
        with pytest.raises(RuleError, match="include"):
            load_custom_rules(cfg)

    def test_rejects_unknown_field(self):
        cfg = config_mod.default_config()
        cfg["rules"] = [{"id": "typo", "include": ["*"], "categry": "oops"}]
        with pytest.raises(RuleError, match="unknown field"):
            load_custom_rules(cfg)

    def test_rejects_absolute_glob(self):
        cfg = config_mod.default_config()
        cfg["rules"] = [{"id": "bad_glob", "include": ["/etc/passwd"]}]
        with pytest.raises(RuleError):
            load_custom_rules(cfg)

    def test_rejects_glob_with_dotdot(self):
        cfg = config_mod.default_config()
        cfg["rules"] = [{"id": "bad_glob", "include": ["../../etc/passwd"]}]
        with pytest.raises(RuleError):
            load_custom_rules(cfg)

    def test_rejects_bad_risk_value(self):
        cfg = config_mod.default_config()
        cfg["rules"] = [{"id": "bad_risk", "include": ["*"], "risk": "extreme"}]
        with pytest.raises(RuleError):
            load_custom_rules(cfg)

    def test_include_accepts_single_string(self):
        cfg = config_mod.default_config()
        cfg["rules"] = [{"id": "single", "include": "Downloads/*.iso"}]
        rules = load_custom_rules(cfg)
        assert rules[0].include_globs == ("Downloads/*.iso",)


def test_unknown_override_ids_flags_typos():
    cfg = config_mod.default_config()
    cfg["rule_overrides"] = {"system_caches": False, "sysetm_cachse": True}
    assert unknown_override_ids(cfg) == ["sysetm_cachse"]


def test_unknown_param_override_ids_flags_typos():
    cfg = config_mod.default_config()
    cfg["rule_param_overrides"] = {"sysetm_cachse": {"min_age_days": 1}}
    assert unknown_param_override_ids(cfg) == ["sysetm_cachse"]


class TestApplyParamOverrides:
    def test_overrides_thresholds(self):
        cfg = config_mod.default_config()
        cfg["rule_param_overrides"] = {"system_caches": {"min_age_days": 99}}
        rules = apply_param_overrides(list(BUILTIN_RULES), cfg)
        rule = next(r for r in rules if r.id == "system_caches")
        assert rule.min_age_days == 99

    def test_untouched_rules_pass_through_unchanged(self):
        cfg = config_mod.default_config()
        cfg["rule_param_overrides"] = {"system_caches": {"min_age_days": 99}}
        rules = apply_param_overrides(list(BUILTIN_RULES), cfg)
        other = next(r for r in rules if r.id == "logs")
        original = next(r for r in BUILTIN_RULES if r.id == "logs")
        assert other is original

    def test_no_overrides_returns_same_list(self):
        cfg = config_mod.default_config()
        rules = list(BUILTIN_RULES)
        assert apply_param_overrides(rules, cfg) is rules
