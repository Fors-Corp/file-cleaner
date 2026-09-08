"""Builtin cleanup rule packs, plus loading of user-defined rules.

Each rule describes a *category* of junk: where to look (scope), what glob
patterns count as a match, and safety metadata (risk level, whether it's
enabled by default). Rules never see file contents — only paths, sizes, and
modification times.

Order matters: more specific rules come before broader ones so that when
two rules match the same path the more descriptive label wins.
"""

from __future__ import annotations

from typing import Any

from filecleaner.models import Rule


class RuleError(Exception):
    """A custom rule in the config file is invalid."""


BUILTIN_RULES: tuple[Rule, ...] = (
    # ----- Logs ------------------------------------------------------------
    Rule(
        id="crash_reports",
        label="Crash & diagnostic reports",
        category="Logs",
        description="~/Library/Logs/DiagnosticReports — crash logs",
        enabled_by_default=True,
        risk="low",
        kind="file",
        scope="home",
        include_globs=("Library/Logs/DiagnosticReports/**/*",),
        min_age_days=0,
    ),
    Rule(
        id="logs",
        label="User logs",
        category="Logs",
        description="~/Library/Logs — application log files older than a week",
        enabled_by_default=True,
        risk="low",
        kind="file",
        scope="home",
        include_globs=("Library/Logs/**/*",),
        min_age_days=7,
    ),
    # ----- Caches ----------------------------------------------------------
    Rule(
        id="browser_caches",
        label="Browser caches",
        category="Caches",
        description="Safari / Chrome / Firefox / Edge on-disk HTTP caches",
        enabled_by_default=True,
        risk="low",
        kind="dir",
        scope="home",
        include_globs=(
            "Library/Caches/com.apple.Safari/*",
            "Library/Caches/Google/Chrome/*",
            "Library/Application Support/Google/Chrome/*/Cache",
            "Library/Application Support/Google/Chrome/*/Code Cache",
            "Library/Caches/Firefox/*",
            "Library/Application Support/Firefox/Profiles/*/cache2",
            "Library/Caches/com.microsoft.edgemac/*",
        ),
        min_age_days=1,
    ),
    Rule(
        id="system_caches",
        label="Application caches",
        category="Caches",
        description="~/Library/Caches/* — regenerable per-app caches untouched for 3 days",
        enabled_by_default=True,
        risk="low",
        kind="dir",
        scope="home",
        include_globs=("Library/Caches/*",),
        min_age_days=3,
    ),
    # ----- Trash -----------------------------------------------------------
    Rule(
        id="trash",
        label="Trash",
        category="Trash",
        description="~/.Trash — files you already deleted",
        enabled_by_default=True,
        risk="low",
        kind="dir",
        scope="home",
        include_globs=(".Trash/*",),
        min_age_days=0,
    ),
    Rule(
        id="external_trash",
        label="External drive Trash",
        category="Trash",
        description="Per-user Trash folders on external/removable volumes",
        enabled_by_default=True,
        risk="low",
        kind="dir",
        scope="each_volume",
        include_globs=(".Trashes/*",),
        min_age_days=0,
    ),
    # ----- System junk -----------------------------------------------------
    Rule(
        id="ds_store",
        label=".DS_Store files",
        category="System junk",
        description="Finder metadata files scattered across the home directory",
        enabled_by_default=True,
        risk="low",
        kind="file",
        scope="home",
        include_globs=("**/.DS_Store",),
        exclude_globs=("Library/**",),
        min_age_days=0,
    ),
    # ----- Developer -------------------------------------------------------
    Rule(
        id="dev_xcode",
        label="Xcode DerivedData",
        category="Developer",
        description="~/Library/Developer/Xcode/DerivedData — fully regenerated on next build",
        enabled_by_default=True,
        risk="low",
        kind="dir",
        scope="home",
        include_globs=("Library/Developer/Xcode/DerivedData/*",),
        min_age_days=3,
    ),
    Rule(
        id="dev_xcode_device_support",
        label="Xcode iOS DeviceSupport",
        category="Developer",
        description="~/Library/Developer/Xcode/iOS DeviceSupport — debug symbols per iOS version, "
        "re-downloaded automatically when that device is next connected",
        enabled_by_default=True,
        risk="low",
        kind="dir",
        scope="home",
        include_globs=("Library/Developer/Xcode/iOS DeviceSupport/*",),
        min_age_days=30,
    ),
    Rule(
        id="dev_simulator_caches",
        label="iOS Simulator caches",
        category="Developer",
        description="~/Library/Developer/CoreSimulator/Caches — simulator runtime caches",
        enabled_by_default=True,
        risk="low",
        kind="dir",
        scope="home",
        include_globs=("Library/Developer/CoreSimulator/Caches/*",),
        min_age_days=7,
    ),
    Rule(
        id="dev_xcode_archives",
        label="Xcode Archives (opt-in)",
        category="Developer (opt-in)",
        description="~/Library/Developer/Xcode/Archives — app archives you may still need for "
        "symbolicating crash reports of shipped builds",
        enabled_by_default=False,
        risk="medium",
        kind="dir",
        scope="home",
        include_globs=("Library/Developer/Xcode/Archives/*",),
        min_age_days=90,
    ),
    Rule(
        id="dev_npm_cache",
        label="npm/yarn/pnpm package caches",
        category="Developer",
        description="Global JS package manager caches — re-downloadable",
        enabled_by_default=True,
        risk="low",
        kind="dir",
        scope="home",
        include_globs=(
            ".npm/_cacache/*",
            "Library/Caches/Yarn/*",
            "Library/pnpm/store/*",
            ".cache/yarn/*",
        ),
        min_age_days=3,
    ),
    Rule(
        id="dev_pip_cache",
        label="pip / uv package caches",
        category="Developer",
        description="Python package manager caches — re-downloadable",
        enabled_by_default=True,
        risk="low",
        kind="dir",
        scope="home",
        include_globs=(
            "Library/Caches/pip/*",
            "Library/Caches/uv/*",
            ".cache/pip/*",
            ".cache/uv/*",
        ),
        min_age_days=3,
    ),
    Rule(
        id="dev_homebrew_cache",
        label="Homebrew download cache",
        category="Developer",
        description="~/Library/Caches/Homebrew — downloaded bottles/archives, kept after install",
        enabled_by_default=True,
        risk="low",
        kind="dir",
        scope="home",
        include_globs=("Library/Caches/Homebrew/*",),
        min_age_days=3,
    ),
    Rule(
        id="dev_gradle_cache",
        label="Gradle caches",
        category="Developer",
        description="~/.gradle/caches — re-downloadable build dependencies",
        enabled_by_default=True,
        risk="low",
        kind="dir",
        scope="home",
        include_globs=(".gradle/caches/*",),
        min_age_days=14,
    ),
    Rule(
        id="dev_cargo_cache",
        label="Cargo registry cache",
        category="Developer",
        description="~/.cargo/registry/cache — downloaded crate archives, re-fetched on demand",
        enabled_by_default=True,
        risk="low",
        kind="dir",
        scope="home",
        include_globs=(".cargo/registry/cache/*",),
        min_age_days=14,
    ),
    Rule(
        id="dev_docker_reclaimable",
        label="Docker Desktop logs (opt-in)",
        category="Developer (opt-in)",
        description="Docker Desktop log data under Library/Containers — NOT images/volumes "
        "(use `docker system prune` for those, since they need Docker's own bookkeeping)",
        enabled_by_default=False,
        risk="medium",
        kind="dir",
        scope="home",
        include_globs=("Library/Containers/com.docker.docker/Data/log/*",),
        min_age_days=7,
    ),
    Rule(
        id="dev_node_modules",
        label="Old node_modules directories (opt-in)",
        category="Developer (opt-in)",
        description="node_modules folders not modified in 30 days — regenerable via package "
        "manager install, but off by default since a project might still be in active use",
        enabled_by_default=False,
        risk="medium",
        kind="dir",
        scope="home",
        include_globs=("**/node_modules",),
        exclude_globs=("Library/**",),
        min_age_days=30,
    ),
    # ----- Personal (opt-in) ----------------------------------------------
    Rule(
        id="mail_downloads",
        label="Mail attachment downloads (opt-in)",
        category="Personal (opt-in)",
        description="Copies of attachments opened from Apple Mail — the originals stay in the message",
        enabled_by_default=False,
        risk="medium",
        kind="file",
        scope="home",
        include_globs=("Library/Containers/com.apple.mail/Data/Library/Mail Downloads/**/*",),
        min_age_days=30,
    ),
    Rule(
        id="old_downloads",
        label="Old files in Downloads (opt-in)",
        category="Personal (opt-in)",
        description="Files in ~/Downloads untouched for 90 days — off by default, these are "
        "personal files, not junk",
        enabled_by_default=False,
        risk="medium",
        kind="file",
        scope="home",
        include_globs=("Downloads/*",),
        min_age_days=90,
    ),
)

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
