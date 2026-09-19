"""Builtin cleanup rule packs, plus loading of user-defined rules.

Each rule describes a *category* of junk: where to look (scope), what glob
patterns count as a match, and safety metadata (risk level, whether it's
enabled by default). Rules never see file contents — only paths, sizes, and
modification times.

Order matters: more specific rules come before broader ones so that when
two rules match the same path the more descriptive label wins.
"""

from __future__ import annotations

import dataclasses
import json
from importlib import resources
from typing import Any

from filecleaner.models import Rule


class RuleError(Exception):
    """A custom rule in the config file is invalid."""


_BUILTIN_RULE_FIELDS = (
    "id",
    "label",
    "category",
    "description",
    "enabled_by_default",
    "risk",
    "kind",
    "scope",
    "include_globs",
    "exclude_globs",
    "min_age_days",
    "min_size_bytes",
)


def _load_builtin_rules() -> tuple[Rule, ...]:
    """The builtin rules live in ``builtin_rules.json`` rather than in code so
    that the Rust port compiles in the very same definitions: one list, two
    readers. Every field is spelled out for every rule — no defaults to drift."""
    document = json.loads(resources.files("filecleaner").joinpath("builtin_rules.json").read_text(encoding="utf-8"))
    loaded = []
    for entry in document["rules"]:
        if tuple(entry) != _BUILTIN_RULE_FIELDS:
            raise ValueError(f"builtin rule {entry.get('id')!r}: expected exactly the fields {_BUILTIN_RULE_FIELDS}")
        globs = {key: tuple(entry[key]) for key in ("include_globs", "exclude_globs")}
        loaded.append(Rule(**{**entry, **globs}))
    return tuple(loaded)


BUILTIN_RULES: tuple[Rule, ...] = _load_builtin_rules()

for _rule in BUILTIN_RULES:
    _rule.validate()

_CUSTOM_RULE_FIELDS = {
    "id",
    "label",
    "category",
    "description",
    "kind",
    "scope",
    "include",
    "exclude",
    "min_age_days",
    "min_size_bytes",
    "risk",
    "enabled",
}


def _as_str_list(value: Any, rule_id: str, field: str) -> tuple[str, ...]:
    if isinstance(value, str):
        value = [value]
    if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
        raise RuleError(f"rule {rule_id!r}: {field} must be a string or a list of strings")
    return tuple(value)


def _as_int(raw: dict[str, Any], rule_id: str, field: str, default: int) -> int:
    value = raw.get(field, default)
    if isinstance(value, bool) or not isinstance(value, int):
        raise RuleError(f"rule {rule_id!r}: {field} must be an integer")
    return value


def load_custom_rules(config: dict[str, Any]) -> list[Rule]:
    """Parse ``[[rules]]`` tables from the config into validated ``Rule`` objects."""
    raw_rules = config.get("rules") or []
    builtin_ids = {r.id for r in BUILTIN_RULES}
    seen: set[str] = set()
    rules: list[Rule] = []
    for index, raw in enumerate(raw_rules):
        if not isinstance(raw, dict):
            raise RuleError(f"rules[{index}]: expected a table")
        unknown = set(raw) - _CUSTOM_RULE_FIELDS
        if unknown:
            raise RuleError(f"rules[{index}]: unknown field(s) {', '.join(sorted(unknown))}")
        rule_id = raw.get("id")
        if not isinstance(rule_id, str) or not rule_id:
            raise RuleError(f"rules[{index}]: 'id' is required")
        if rule_id in builtin_ids:
            raise RuleError(f"rule {rule_id!r}: id clashes with a builtin rule")
        if rule_id in seen:
            raise RuleError(f"rule {rule_id!r}: duplicate id")
        seen.add(rule_id)

        if "include" not in raw:
            raise RuleError(f"rule {rule_id!r}: 'include' (list of globs) is required")

        enabled = raw.get("enabled", True)
        if not isinstance(enabled, bool):
            raise RuleError(f"rule {rule_id!r}: enabled must be true/false")

        rule = Rule(
            id=rule_id,
            label=str(raw.get("label") or rule_id),
            category=str(raw.get("category") or "Custom"),
            description=str(raw.get("description") or ""),
            enabled_by_default=enabled,
            risk=str(raw.get("risk") or "medium"),
            kind=str(raw.get("kind") or "file"),
            scope=str(raw.get("scope") or "home"),
            include_globs=_as_str_list(raw["include"], rule_id, "include"),
            exclude_globs=_as_str_list(raw.get("exclude", []), rule_id, "exclude"),
            min_age_days=_as_int(raw, rule_id, "min_age_days", 0),
            min_size_bytes=_as_int(raw, rule_id, "min_size_bytes", 0),
            source="custom",
        )
        try:
            rule.validate()
        except ValueError as exc:
            raise RuleError(str(exc)) from exc
        rules.append(rule)
    return rules


def all_rules(config: dict[str, Any] | None = None) -> tuple[Rule, ...]:
    """Builtin rules followed by any custom rules from ``config``."""
    if config is None:
        return BUILTIN_RULES
    return (*BUILTIN_RULES, *load_custom_rules(config))


def rules_by_id(config: dict[str, Any] | None = None) -> dict[str, Rule]:
    return {r.id: r for r in all_rules(config)}


def unknown_override_ids(config: dict[str, Any]) -> list[str]:
    """Rule ids referenced in ``rule_overrides`` that no rule defines (typos)."""
    known = rules_by_id(config)
    return sorted(rid for rid in config.get("rule_overrides", {}) if rid not in known)


def unknown_param_override_ids(config: dict[str, Any]) -> list[str]:
    """Rule ids referenced in ``rule_param_overrides`` that no rule defines (typos)."""
    known = rules_by_id(config)
    return sorted(rid for rid in config.get("rule_param_overrides", {}) if rid not in known)


def apply_param_overrides(rules: list[Rule], config: dict[str, Any]) -> list[Rule]:
    """Apply ``rule_param_overrides`` (per-rule min_age_days/min_size_bytes
    tweaks) on top of a rule list, without redefining any rule as custom."""
    overrides = config.get("rule_param_overrides", {})
    if not overrides:
        return rules
    return [dataclasses.replace(rule, **overrides[rule.id]) if rule.id in overrides else rule for rule in rules]
