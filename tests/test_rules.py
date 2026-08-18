from filecleaner.rules import BUILTIN_RULES, rules_by_id


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
