//! `filecleaner.rules` and `models.Rule`: the builtin rules, custom rules
//! from the config, and which of them a scan runs.
//!
//! The builtin rules are not written here. They are the package's own
//! `builtin_rules.json`, compiled in: one list, two readers.

use std::collections::HashSet;

use serde::Deserialize;
use toml::{Table, Value};

use crate::pyjson::J;

const BUILTIN_RULES_JSON: &str = include_str!("../../../src/filecleaner/builtin_rules.json");
const CUSTOM_RULE_FIELDS: [&str; 12] = [
    "id", "label", "category", "description", "kind", "scope", "include", "exclude", "min_age_days",
    "min_size_bytes", "risk", "enabled",
];

#[derive(Clone, Debug, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Rule {
    pub id: String,
    pub label: String,
    pub category: String,
    pub description: String,
    pub enabled_by_default: bool,
    pub risk: String,
    pub kind: String,
    pub scope: String,
    pub include_globs: Vec<String>,
    pub exclude_globs: Vec<String>,
    pub min_age_days: i64,
    pub min_size_bytes: i64,
    #[serde(default = "builtin")]
    pub source: String,
}

fn builtin() -> String {
    "builtin".to_owned()
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BuiltinRules {
    #[serde(rename = "_comment")]
    _comment: Vec<String>,
    rules: Vec<Rule>,
}

/// `repr(str)`, as far as an error message needs it.
pub fn repr(text: &str) -> String {
    let quote = if text.contains('\'') && !text.contains('"') { '"' } else { '\'' };
    let mut out = String::from(quote);
    for c in text.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c == quote => {
                out.push('\\');
                out.push(c);
            }
            c => out.push(c),
        }
    }
    out.push(quote);
    out
}

impl Rule {
    /// `Rule.validate`: the first problem found, in Python's words.
    pub fn validate(&self) -> Result<(), String> {
        let id = repr(&self.id);
        let bare: String = self.id.chars().filter(|c| *c != '_' && *c != '-').collect();
        if bare.is_empty() || !bare.chars().all(char::is_alphanumeric) {
            return Err(format!("rule id {id} must be alphanumeric (underscores/hyphens allowed)"));
        }
        if self.label.is_empty() {
            return Err(format!("rule {id}: label is required"));
        }
        if self.category.is_empty() {
            return Err(format!("rule {id}: category is required"));
        }
        if !["file", "dir"].contains(&self.kind.as_str()) {
            return Err(format!("rule {id}: kind must be one of ('file', 'dir'), got {}", repr(&self.kind)));
        }
        if !["home", "each_volume"].contains(&self.scope.as_str()) {
            return Err(format!("rule {id}: scope must be one of ('home', 'each_volume'), got {}", repr(&self.scope)));
        }
        if !["low", "medium", "high"].contains(&self.risk.as_str()) {
            return Err(format!("rule {id}: risk must be one of ('low', 'medium', 'high'), got {}", repr(&self.risk)));
        }
        if self.include_globs.is_empty() {
            return Err(format!("rule {id}: at least one include glob is required"));
        }
        for glob in self.include_globs.iter().chain(&self.exclude_globs) {
            if glob.is_empty() || glob.starts_with('/') || glob.starts_with('~') {
                return Err(format!(
                    "rule {id}: glob {} must be relative to the scan root (no leading '/' or '~')",
                    repr(glob)
                ));
            }
            if glob.split('/').any(|part| part == "..") {
                return Err(format!("rule {id}: glob {} must not contain '..'", repr(glob)));
            }
        }
        if self.min_age_days < 0 {
            return Err(format!("rule {id}: min_age_days must be >= 0"));
        }
        if self.min_size_bytes < 0 {
            return Err(format!("rule {id}: min_size_bytes must be >= 0"));
        }
        Ok(())
    }

    /// `Rule.to_dict()`.
    pub fn to_json(&self) -> Vec<(String, J)> {
        let J::Dict(pairs) = J::dict([
            ("id", J::str(&self.id)),
            ("label", J::str(&self.label)),
            ("category", J::str(&self.category)),
            ("description", J::str(&self.description)),
            ("enabled_by_default", J::Bool(self.enabled_by_default)),
            ("risk", J::str(&self.risk)),
            ("kind", J::str(&self.kind)),
            ("scope", J::str(&self.scope)),
            ("include_globs", J::strings(&self.include_globs)),
            ("exclude_globs", J::strings(&self.exclude_globs)),
            ("min_age_days", J::Int(self.min_age_days)),
            ("min_size_bytes", J::Int(self.min_size_bytes)),
            ("source", J::str(&self.source)),
        ]) else {
            unreachable!("J::dict builds a Dict")
        };
        pairs
    }
}

pub fn builtin_rules() -> Result<Vec<Rule>, String> {
    let document: BuiltinRules =
        serde_json::from_str(BUILTIN_RULES_JSON).map_err(|err| format!("builtin_rules.json: {err}"))?;
    for rule in &document.rules {
        rule.validate()?;
    }
    Ok(document.rules)
}

/// Python's `value or default` followed by `str(...)`, for a field that is
/// text. Python would also stringify a number or a list here; the port
/// refuses those instead of guessing at `str()` of a TOML value.
fn text_or(raw: &Table, rule_id: &str, field: &str, default: &str) -> Result<String, String> {
    match raw.get(field) {
        None => Ok(default.to_owned()),
        Some(Value::String(text)) if text.is_empty() => Ok(default.to_owned()),
        Some(Value::String(text)) => Ok(text.clone()),
        Some(_) => Err(format!("rule {}: {field} must be a string", repr(rule_id))),
    }
}

fn str_list(value: Option<&Value>, rule_id: &str, field: &str) -> Result<Vec<String>, String> {
    let wrong = || format!("rule {}: {field} must be a string or a list of strings", repr(rule_id));
    match value {
        None => Ok(Vec::new()),
        Some(Value::String(text)) => Ok(vec![text.clone()]),
        Some(Value::Array(items)) => {
            items.iter().map(|item| item.as_str().map(str::to_owned).ok_or_else(wrong)).collect()
        }
        Some(_) => Err(wrong()),
    }
}

fn int_or(raw: &Table, rule_id: &str, field: &str, default: i64) -> Result<i64, String> {
    match raw.get(field) {
        None => Ok(default),
        Some(Value::Integer(number)) => Ok(*number),
        Some(_) => Err(format!("rule {}: {field} must be an integer", repr(rule_id))),
    }
}

/// `rules.load_custom_rules`: the `[[rules]]` tables of the config.
pub fn custom_rules(config: &Table, builtin: &[Rule]) -> Result<Vec<Rule>, String> {
    let raw_rules = match config.get("rules") {
        Some(Value::Array(items)) => items.as_slice(),
        _ => &[],
    };
    let builtin_ids: HashSet<&str> = builtin.iter().map(|rule| rule.id.as_str()).collect();
    let mut seen: HashSet<String> = HashSet::new();
    let mut rules = Vec::new();
    for (index, raw) in raw_rules.iter().enumerate() {
        let Value::Table(raw) = raw else { return Err(format!("rules[{index}]: expected a table")) };
        let mut unknown: Vec<&str> =
            raw.keys().map(String::as_str).filter(|key| !CUSTOM_RULE_FIELDS.contains(key)).collect();
        if !unknown.is_empty() {
            unknown.sort_unstable();
            return Err(format!("rules[{index}]: unknown field(s) {}", unknown.join(", ")));
        }
        let rule_id = match raw.get("id") {
            Some(Value::String(id)) if !id.is_empty() => id.clone(),
            _ => return Err(format!("rules[{index}]: 'id' is required")),
        };
        if builtin_ids.contains(rule_id.as_str()) {
            return Err(format!("rule {}: id clashes with a builtin rule", repr(&rule_id)));
        }
        if !seen.insert(rule_id.clone()) {
            return Err(format!("rule {}: duplicate id", repr(&rule_id)));
        }
        if !raw.contains_key("include") {
            return Err(format!("rule {}: 'include' (list of globs) is required", repr(&rule_id)));
        }
        let enabled = match raw.get("enabled") {
            None => true,
            Some(Value::Boolean(flag)) => *flag,
            Some(_) => return Err(format!("rule {}: enabled must be true/false", repr(&rule_id))),
        };
        let rule = Rule {
            label: text_or(raw, &rule_id, "label", &rule_id)?,
            category: text_or(raw, &rule_id, "category", "Custom")?,
            description: text_or(raw, &rule_id, "description", "")?,
            enabled_by_default: enabled,
            risk: text_or(raw, &rule_id, "risk", "medium")?,
            kind: text_or(raw, &rule_id, "kind", "file")?,
            scope: text_or(raw, &rule_id, "scope", "home")?,
            include_globs: str_list(raw.get("include"), &rule_id, "include")?,
            exclude_globs: str_list(raw.get("exclude"), &rule_id, "exclude")?,
            min_age_days: int_or(raw, &rule_id, "min_age_days", 0)?,
            min_size_bytes: int_or(raw, &rule_id, "min_size_bytes", 0)?,
            source: "custom".to_owned(),
            id: rule_id,
        };
        rule.validate()?;
        rules.push(rule);
    }
    Ok(rules)
}

/// `rules.all_rules(config)`: builtin first, then custom, in file order.
pub fn all_rules(config: &Table) -> Result<Vec<Rule>, String> {
    let mut rules = builtin_rules()?;
    let custom = custom_rules(config, &rules)?;
    rules.extend(custom);
    Ok(rules)
}

fn table<'a>(config: &'a Table, key: &str) -> Option<&'a Table> {
    config.get(key).and_then(Value::as_table)
}

/// `config.is_rule_enabled`.
pub fn is_enabled(config: &Table, rule: &Rule) -> bool {
    table(config, "rule_overrides")
        .and_then(|overrides| overrides.get(&rule.id))
        .and_then(Value::as_bool)
        .unwrap_or(rule.enabled_by_default)
}

/// `rules.apply_param_overrides`.
fn with_param_overrides(mut rules: Vec<Rule>, config: &Table) -> Vec<Rule> {
    let Some(overrides) = table(config, "rule_param_overrides") else { return rules };
    for rule in &mut rules {
        let Some(params) = overrides.get(&rule.id).and_then(Value::as_table) else { continue };
        if let Some(days) = params.get("min_age_days").and_then(Value::as_integer) {
            rule.min_age_days = days;
        }
        if let Some(bytes) = params.get("min_size_bytes").and_then(Value::as_integer) {
            rule.min_size_bytes = bytes;
        }
    }
    rules
}

/// `scanner.select_rules`.
pub fn select(config: &Table, only_rules: Option<&[String]>, include_disabled: bool) -> Result<Vec<Rule>, String> {
    let available = all_rules(config)?;
    let selected: Vec<Rule> = match only_rules {
        Some(only) => {
            let mut unknown: Vec<&str> = only
                .iter()
                .map(String::as_str)
                .filter(|id| !available.iter().any(|rule| rule.id == *id))
                .collect();
            if !unknown.is_empty() {
                unknown.sort_unstable();
                unknown.dedup();
                return Err(format!("unknown rule id(s): {}", unknown.join(", ")));
            }
            available.into_iter().filter(|rule| only.contains(&rule.id)).collect()
        }
        None => available.into_iter().filter(|rule| include_disabled || is_enabled(config, rule)).collect(),
    };
    Ok(with_param_overrides(selected, config))
}

/// `rules.unknown_override_ids` / `unknown_param_override_ids`.
pub fn unknown_ids(config: &Table, key: &str, rules: &[Rule]) -> Vec<String> {
    let mut unknown: Vec<String> = table(config, key)
        .map(|overrides| {
            overrides.keys().filter(|id| !rules.iter().any(|rule| &rule.id == *id)).cloned().collect()
        })
        .unwrap_or_default();
    unknown.sort_unstable();
    unknown
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(text: &str) -> Table {
        text.parse().expect("valid TOML")
    }

    #[test]
    fn the_builtin_rules_load_and_are_valid() {
        let rules = builtin_rules().expect("builtin rules");
        assert!(rules.len() >= 20);
        assert!(rules.iter().all(|rule| rule.source == "builtin"));
        let ids: HashSet<&str> = rules.iter().map(|rule| rule.id.as_str()).collect();
        assert_eq!(ids.len(), rules.len(), "ids are unique");
    }

    #[test]
    fn a_custom_rule_gets_pythons_defaults() {
        let rules = all_rules(&config("[[rules]]\nid = \"mine\"\ninclude = \"**/*.bak\"\n")).expect("rules");
        let mine = rules.last().expect("custom rule");
        assert_eq!(
            (mine.label.as_str(), mine.category.as_str(), mine.risk.as_str(), mine.kind.as_str(), mine.scope.as_str()),
            ("mine", "Custom", "medium", "file", "home")
        );
        assert_eq!(mine.include_globs, ["**/*.bak"]);
        assert!(mine.enabled_by_default && mine.source == "custom");
    }

    #[test]
    fn bad_custom_rules_are_refused_in_pythons_words() {
        for (text, expected) in [
            ("[[rules]]\ninclude = [\"a\"]\n", "rules[0]: 'id' is required"),
            ("[[rules]]\nid = \"logs\"\ninclude = [\"a\"]\n", "rule 'logs': id clashes with a builtin rule"),
            ("[[rules]]\nid = \"x\"\n", "rule 'x': 'include' (list of globs) is required"),
            ("[[rules]]\nid = \"x\"\ninclude = [\"/abs\"]\n", "rule 'x': glob '/abs' must be relative to the scan root (no leading '/' or '~')"),
            ("[[rules]]\nid = \"x\"\ninclude = [\"a/../b\"]\n", "rule 'x': glob 'a/../b' must not contain '..'"),
            ("[[rules]]\nid = \"x\"\ninclude = [\"a\"]\nkind = \"socket\"\n", "rule 'x': kind must be one of ('file', 'dir'), got 'socket'"),
            ("[[rules]]\nid = \"x\"\ninclude = [\"a\"]\nzzz = 1\naaa = 2\n", "rules[0]: unknown field(s) aaa, zzz"),
            ("[[rules]]\nid = \"x\"\ninclude = [\"a\"]\nmin_age_days = \"7\"\n", "rule 'x': min_age_days must be an integer"),
            ("[[rules]]\nid = \"x y\"\ninclude = [\"a\"]\n", "rule id 'x y' must be alphanumeric (underscores/hyphens allowed)"),
        ] {
            assert_eq!(all_rules(&config(text)).unwrap_err(), expected);
        }
    }

    #[test]
    fn selection_honours_overrides_filters_and_thresholds() {
        let cfg = config("[rule_overrides]\nlogs = false\n[rule_param_overrides.crash_reports]\nmin_age_days = 9\n");
        let selected = select(&cfg, None, false).expect("selection");
        assert!(!selected.iter().any(|rule| rule.id == "logs"));
        assert_eq!(selected.iter().find(|rule| rule.id == "crash_reports").map(|rule| rule.min_age_days), Some(9));

        let only = ["logs".to_owned()];
        assert_eq!(select(&cfg, Some(&only), false).expect("only").len(), 1); // a filter ignores enabled state
        let unknown = ["nope".to_owned(), "also_nope".to_owned()];
        assert_eq!(select(&cfg, Some(&unknown), false).unwrap_err(), "unknown rule id(s): also_nope, nope");
    }
}
