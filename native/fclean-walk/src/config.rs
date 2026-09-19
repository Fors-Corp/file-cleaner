//! `filecleaner.config`, the reading half: where the config lives, its
//! defaults, and validation with Python's messages. Nothing here writes.
//! (Python creates a default `config.toml` on first run; the port just uses
//! the defaults. Saving stays with Python until the CLI itself is ported.)

use std::fs;
use std::io;

use toml::{Table, Value};

use crate::pyjson::J;
use crate::pypath::{expanduser, normalise};
use crate::rules::repr;

pub struct Paths {
    pub config_dir: String,
    pub config_file: String,
    pub data_dir: String,
    pub default_quarantine_dir: String,
}

/// `_config_dir_from_env` / `_data_dir_from_env`. `explicit` is where a
/// caller that already knows (a test, the parity tool) says they are.
pub fn paths(
    home: &str,
    explicit: (Option<&str>, Option<&str>),
    env: impl Fn(&str) -> Option<String>,
) -> Result<Paths, String> {
    let set = |name: &str| env(name).filter(|value| !value.is_empty());
    let config_dir = match (explicit.0, set("FILECLEANER_CONFIG_DIR"), set("XDG_CONFIG_HOME")) {
        (Some(dir), _, _) => normalise(dir),
        (None, Some(dir), _) => expanduser(&dir, home)?,
        (None, None, Some(xdg)) => normalise(&format!("{}/filecleaner", expanduser(&xdg, home)?)),
        (None, None, None) => normalise(&format!("{home}/.config/filecleaner")),
    };
    let data_dir = match (explicit.1, set("FILECLEANER_DATA_DIR")) {
        (Some(dir), _) => normalise(dir),
        (None, Some(dir)) => expanduser(&dir, home)?,
        (None, None) => normalise(&format!("{home}/.filecleaner")),
    };
    Ok(Paths {
        config_file: format!("{config_dir}/config.toml"),
        default_quarantine_dir: format!("{data_dir}/quarantine"),
        config_dir,
        data_dir,
    })
}

/// `default_config()`, in `CONFIG_SCHEMA` order — the order `config show`
/// prints them in.
pub fn defaults(paths: &Paths) -> Table {
    let mut config = Table::new();
    config.insert("retention_days".into(), Value::Integer(30));
    config.insert("quarantine_dir".into(), Value::String(paths.default_quarantine_dir.clone()));
    config.insert("volume_local_quarantine".into(), Value::Boolean(true));
    config.insert("protected_paths".into(), Value::Array(Vec::new()));
    config.insert("scan_roots".into(), Value::Array(Vec::new()));
    config.insert("rule_overrides".into(), Value::Table(Table::new()));
    config.insert("hash_duplicates_max_bytes".into(), Value::Integer(2_000_000_000));
    config.insert("rules".into(), Value::Array(Vec::new()));
    config.insert("rule_param_overrides".into(), Value::Table(Table::new()));
    config.insert("scan_concurrency".into(), Value::Integer(4));
    config.insert("active_profile".into(), Value::String(String::new()));
    config
}

/// `type(value).__name__`.
fn type_name(value: &Value) -> &'static str {
    match value {
        Value::String(_) => "str",
        Value::Integer(_) => "int",
        Value::Float(_) => "float",
        Value::Boolean(_) => "bool",
        Value::Datetime(_) => "datetime",
        Value::Array(_) => "list",
        Value::Table(_) => "dict",
    }
}

fn check_int(value: &Value, key: &str, least: i64) -> Result<(), String> {
    let Value::Integer(number) = value else {
        return Err(format!("{key}: expected an integer, got {}", type_name(value)));
    };
    if *number < least {
        return Err(format!("{key}: must be >= {least}, got {number}"));
    }
    Ok(())
}

fn check_str_list(value: &Value, key: &str) -> Result<(), String> {
    match value {
        Value::Array(items) if items.iter().all(Value::is_str) => Ok(()),
        _ => Err(format!("{key}: expected a list of strings")),
    }
}

fn check_overrides(value: &Value, key: &str) -> Result<(), String> {
    let Value::Table(overrides) = value else {
        return Err(format!("{key}: expected a table of rule_id = true/false"));
    };
    for (rule_id, flag) in overrides {
        if !flag.is_bool() {
            return Err(format!("{key}.{rule_id}: expected true/false, got {}", type_name(flag)));
        }
    }
    Ok(())
}

fn check_param_overrides(value: &Value, key: &str) -> Result<(), String> {
    const FIELDS: [&str; 2] = ["min_age_days", "min_size_bytes"];
    let Value::Table(overrides) = value else {
        return Err(format!("{key}: expected a table of rule_id = {{min_age_days=.., min_size_bytes=..}}"));
    };
    for (rule_id, params) in overrides {
        let Value::Table(params) = params else { return Err(format!("{key}.{rule_id}: expected a table")) };
        let mut unknown: Vec<&str> = params.keys().map(String::as_str).filter(|f| !FIELDS.contains(f)).collect();
        if !unknown.is_empty() {
            unknown.sort_unstable();
            let listed: Vec<String> = unknown.iter().map(|field| repr(field)).collect();
            return Err(format!(
                "{key}.{rule_id}: unknown field(s) [{}]; allowed: ['min_age_days', 'min_size_bytes']",
                listed.join(", ")
            ));
        }
        for (field, raw) in params {
            if !matches!(raw, Value::Integer(number) if *number >= 0) {
                return Err(format!("{key}.{rule_id}.{field}: must be a non-negative integer"));
            }
        }
    }
    Ok(())
}

/// `validate_config`: warnings for keys nobody knows, an error for the first
/// value of the wrong shape.
pub fn validate(config: &Table) -> Result<Vec<String>, String> {
    let mut warnings = Vec::new();
    for (key, value) in config {
        match key.as_str() {
            "retention_days" | "hash_duplicates_max_bytes" => check_int(value, key, 0)?,
            "scan_concurrency" => check_int(value, key, 1)?,
            "quarantine_dir" => {
                if !matches!(value, Value::String(text) if !text.trim().is_empty()) {
                    return Err(format!("{key}: expected a non-empty string"));
                }
            }
            "volume_local_quarantine" => {
                if !value.is_bool() {
                    return Err(format!("{key}: expected true/false, got {}", type_name(value)));
                }
            }
            "protected_paths" | "scan_roots" => check_str_list(value, key)?,
            "rule_overrides" => check_overrides(value, key)?,
            "rules" => {
                if !matches!(value, Value::Array(items) if items.iter().all(Value::is_table)) {
                    return Err(format!("{key}: expected an array of tables ([[rules]] blocks)"));
                }
            }
            "rule_param_overrides" => check_param_overrides(value, key)?,
            "active_profile" => {
                if !value.is_str() {
                    return Err(format!("{key}: expected a string"));
                }
            }
            _ => warnings.push(format!("unknown config key {} (ignored)", repr(key))),
        }
    }
    Ok(warnings)
}

/// `load_config`: defaults, overlaid with the file if there is one.
pub fn load(paths: &Paths) -> Result<(Table, Vec<String>), String> {
    let mut config = defaults(paths);
    let text = match fs::read_to_string(&paths.config_file) {
        Ok(text) => text,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok((config, Vec::new())),
        Err(err) => return Err(format!("could not read {}: {err}", paths.config_file)),
    };
    let loaded: Table = text.parse().map_err(|err: toml::de::Error| {
        format!("{} is not valid TOML: {}", paths.config_file, err.message())
    })?;
    for (key, value) in loaded {
        config.insert(key, value); // an existing key keeps its place, as in {**defaults, **loaded}
    }
    let warnings = validate(&config)?;
    Ok((config, warnings))
}

fn strings(config: &Table, key: &str) -> Vec<String> {
    config
        .get(key)
        .and_then(Value::as_array)
        .map(|items| items.iter().filter_map(Value::as_str).map(str::to_owned).collect())
        .unwrap_or_default()
}

pub fn scan_roots(config: &Table) -> Vec<String> {
    strings(config, "scan_roots")
}

/// `extra_protected_paths(config) + data_paths_to_protect(config)`.
pub fn protected_paths(config: &Table, paths: &Paths, home: &str) -> Result<Vec<String>, String> {
    let mut protected = Vec::new();
    for path in strings(config, "protected_paths") {
        protected.push(expanduser(&path, home)?);
    }
    protected.push(paths.config_dir.clone());
    protected.push(paths.data_dir.clone());
    let quarantine = config.get("quarantine_dir").and_then(Value::as_str).filter(|dir| !dir.is_empty());
    protected.push(expanduser(quarantine.unwrap_or(&paths.default_quarantine_dir), home)?);
    Ok(protected)
}

/// A config value the way `output.to_jsonable` would hand it to `json.dumps`.
pub fn to_json(value: &Value) -> J {
    match value {
        Value::String(text) => J::Str(text.clone()),
        Value::Integer(number) => J::Int(*number),
        Value::Float(number) => J::Float(*number),
        Value::Boolean(flag) => J::Bool(*flag),
        Value::Datetime(when) => J::Str(when.to_string()),
        Value::Array(items) => J::List(items.iter().map(to_json).collect()),
        Value::Table(table) => J::Dict(table.iter().map(|(key, item)| (key.clone(), to_json(item))).collect()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn no_env(_: &str) -> Option<String> {
        None
    }

    #[test]
    fn paths_follow_the_same_environment_variables() {
        let default = paths("/Users/x", (None, None), no_env).expect("paths");
        assert_eq!(default.config_file, "/Users/x/.config/filecleaner/config.toml");
        assert_eq!(default.default_quarantine_dir, "/Users/x/.filecleaner/quarantine");

        let env = |name: &str| match name {
            "XDG_CONFIG_HOME" => Some("~/xdg/".to_owned()),
            "FILECLEANER_DATA_DIR" => Some("/data//fc".to_owned()),
            "FILECLEANER_CONFIG_DIR" => Some(String::new()), // set but empty: ignored, as in Python
            _ => None,
        };
        let from_env = paths("/Users/x", (None, None), env).expect("paths");
        assert_eq!((from_env.config_dir.as_str(), from_env.data_dir.as_str()), ("/Users/x/xdg/filecleaner", "/data/fc"));

        let told = paths("/Users/x", (Some("/c"), Some("/d")), env).expect("paths");
        assert_eq!((told.config_dir.as_str(), told.data_dir.as_str()), ("/c", "/d"));
    }

    #[test]
    fn bad_values_are_refused_in_pythons_words() {
        for (text, expected) in [
            ("retention_days = \"30\"", "retention_days: expected an integer, got str"),
            ("retention_days = true", "retention_days: expected an integer, got bool"),
            ("retention_days = -1", "retention_days: must be >= 0, got -1"),
            ("scan_concurrency = 0", "scan_concurrency: must be >= 1, got 0"),
            ("quarantine_dir = \"  \"", "quarantine_dir: expected a non-empty string"),
            ("volume_local_quarantine = 1", "volume_local_quarantine: expected true/false, got int"),
            ("scan_roots = [1]", "scan_roots: expected a list of strings"),
            ("rule_overrides = 3", "rule_overrides: expected a table of rule_id = true/false"),
            ("[rule_overrides]\nlogs = \"no\"", "rule_overrides.logs: expected true/false, got str"),
            ("rules = [1]", "rules: expected an array of tables ([[rules]] blocks)"),
            ("active_profile = 1", "active_profile: expected a string"),
            ("[rule_param_overrides.logs]\nzz = 1\naa = 2", "rule_param_overrides.logs: unknown field(s) ['aa', 'zz']; allowed: ['min_age_days', 'min_size_bytes']"),
            ("[rule_param_overrides.logs]\nmin_age_days = -2", "rule_param_overrides.logs.min_age_days: must be a non-negative integer"),
            ("[rule_param_overrides]\nlogs = 5", "rule_param_overrides.logs: expected a table"),
        ] {
            let config: Table = text.parse().expect("valid TOML");
            assert_eq!(validate(&config).unwrap_err(), expected, "{text}");
        }
    }

    #[test]
    fn unknown_keys_warn_and_known_keys_keep_their_place() {
        let dir = std::env::temp_dir().join(format!("fclean-walk-config-{}", std::process::id()));
        fs::create_dir_all(&dir).expect("scratch dir");
        let paths = paths("/Users/x", (dir.to_str(), Some("/d")), no_env).expect("paths");
        fs::write(&paths.config_file, "mystery = 1\nretention_days = 7\n").expect("config file");

        let (config, warnings) = load(&paths).expect("config");

        assert_eq!(warnings, ["unknown config key 'mystery' (ignored)"]);
        let keys: Vec<&str> = config.keys().map(String::as_str).collect();
        assert_eq!((keys[0], *keys.last().expect("keys")), ("retention_days", "mystery"));
        assert_eq!(config["retention_days"].as_integer(), Some(7));
        assert_eq!(config["quarantine_dir"].as_str(), Some("/d/quarantine"));
        let _ = fs::remove_dir_all(&dir);
    }
}
