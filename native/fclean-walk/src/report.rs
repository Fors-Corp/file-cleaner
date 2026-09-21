//! What `fclean scan --json` and `fclean config show --json` print, with no
//! Python in the loop: config, rules, selection, scan roots, the scan, and
//! the report. Read-only — in particular, unlike `fclean scan`, nothing is
//! appended to the audit log; that arrives with the command itself.

use std::ffi::CStr;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use serde::Deserialize;

use crate::pyjson::{dumps, J};
use crate::pypath::expanduser;
use crate::rules::{self, Rule};
use crate::{config, fail, native_scan, safety, volumes, WalkSpec};

/// `scanner._NEVER_DESCEND` and `scanner._MAX_ERRORS`.
const NEVER_DESCEND: [&str; 1] = [".git"];
const MAX_ERRORS: usize = 200;

/// Where things are, in every command's request. Each defaults to what
/// Python would find for itself.
#[derive(Deserialize)]
pub struct Setup {
    home: Option<String>,
    volumes_dir: Option<String>,
    self_dirs: Option<Vec<String>>,
    config_dir: Option<String>,
    data_dir: Option<String>,
    #[serde(default)]
    pub threads: usize,
}

#[derive(Deserialize)]
pub struct NativeRequest {
    #[serde(flatten)]
    pub setup: Setup,
    /// `fclean scan [ROOT] --rules a,b --include-disabled --exclude PATH`.
    root: Option<String>,
    only_rules: Option<Vec<String>>,
    #[serde(default)]
    include_disabled: bool,
    #[serde(default)]
    extra_excludes: Vec<String>,
    /// The clock, when a caller needs two scans to agree about ages.
    now: Option<f64>,
}

pub struct Loaded {
    pub env: safety::Environment,
    pub paths: config::Paths,
    pub config: toml::Table,
    pub rules: Vec<Rule>,
}

/// Where home, the config and the data are: all that a command which reads
/// no config needs (`audit` and `backups list` load none in Python either).
pub fn locate(request: &Setup) -> (safety::Environment, config::Paths) {
    let home = request
        .home
        .clone()
        .or_else(|| std::env::var("HOME").ok().filter(|home| !home.is_empty()))
        .unwrap_or_else(|| fail("HOME is not set".to_owned()));
    let cwd = std::env::current_dir().ok().and_then(|dir| dir.to_str().map(str::to_owned)).unwrap_or_else(|| "/".into());
    let own_dir = || {
        let exe = std::env::current_exe().ok().and_then(|exe| exe.parent().and_then(|dir| dir.to_str().map(str::to_owned)));
        exe.and_then(|dir| safety::resolve(&dir, "/").ok()).into_iter().collect()
    };
    let env = safety::Environment {
        home,
        volumes_dir: request.volumes_dir.clone().unwrap_or_else(|| "/Volumes".to_owned()),
        self_dirs: request.self_dirs.clone().unwrap_or_else(own_dir),
        cwd,
    };
    let explicit = (request.config_dir.as_deref(), request.data_dir.as_deref());
    let paths = config::paths(&env.home, explicit, |name| std::env::var(name).ok())
        .unwrap_or_else(|err| fail(format!("Configuration error: {err}")));
    (env, paths)
}

pub fn load(request: &Setup) -> Loaded {
    let (env, paths) = locate(request);
    let (config, warnings) = config::load(&paths).unwrap_or_else(|err| fail(format!("Configuration error: {err}")));
    let rules = rules::all_rules(&config).unwrap_or_else(|err| fail(format!("Invalid custom rule in config: {err}")));
    for warning in warnings {
        eprintln!("Warning: {warning}");
    }
    for key in ["rule_overrides", "rule_param_overrides"] {
        for id in rules::unknown_ids(&config, key, &rules) {
            eprintln!("Warning: {key} has unknown rule id {} (typo?)", rules::repr(&id));
        }
    }
    Loaded { env, paths, config, rules }
}

/// `os.strerror`.
pub fn strerror(errno: i32) -> String {
    let mut buffer = [0 as libc::c_char; 256];
    if unsafe { libc::strerror_r(errno, buffer.as_mut_ptr(), buffer.len()) } != 0 {
        return format!("Unknown error: {errno}");
    }
    unsafe { CStr::from_ptr(buffer.as_ptr()) }.to_string_lossy().into_owned()
}

/// `scanner._same_path`.
fn same_path(a: &str, b: &str, cwd: &str) -> bool {
    match (safety::resolve(a, cwd), safety::resolve(b, cwd)) {
        (Ok(a), Ok(b)) => a == b,
        _ => a == b,
    }
}

/// `Candidate.to_dict`, as a scan report and a plan file both hold it.
pub fn candidate_json(hit: &crate::Hit, rule: &Rule) -> J {
    J::dict([
        ("path", J::str(&hit.path)),
        ("size_bytes", J::UInt(hit.size)),
        ("is_dir", J::Bool(hit.is_dir)),
        ("mtime", J::Float(hit.mtime)),
        ("rule_id", J::str(&rule.id)),
        ("category", J::str(&rule.category)),
        ("risk", J::str(&rule.risk)),
    ])
}

/// What `scanner.run_scan` returns, with what a report needs to describe it.
pub struct Scan {
    pub roots: Vec<String>,
    pub scanned: crate::Scanned,
    /// The rule behind each walk, by `Hit::walk`.
    pub owners: Vec<Rule>,
}

/// `fclean scan` and `fclean clean`, up to the point where one prints a
/// report and the other saves a plan.
pub fn scan(request: &NativeRequest) -> Scan {
    let Loaded { env, paths, config, rules: _ } = load(&request.setup);
    let selected = rules::select(&config, request.only_rules.as_deref(), request.include_disabled)
        .unwrap_or_else(|err| fail(err));

    // scanner._scan_setup
    let expand = |path: &str| expanduser(path, &env.home).unwrap_or_else(|err| fail(err));
    let asked = request.root.as_deref().map(expand).unwrap_or_else(|| env.cwd.clone());
    let root = safety::resolve(&asked, &env.cwd).unwrap_or_else(|_| fail(format!("cannot resolve {asked}")));
    if request.root.is_some() && !std::fs::metadata(&root).map(|meta| meta.is_dir()).unwrap_or(false) {
        fail(format!("--root {root} is not a directory."));
    }
    let mut extra_protected = config::protected_paths(&config, &paths, &env.home).unwrap_or_else(|err| fail(err));
    extra_protected.extend(request.extra_excludes.iter().map(|path| expand(path)));
    let (roots, root_in_roots, volume_roots) = if same_path(&root, &env.home, &env.cwd) {
        let roots = volumes::default_scan_roots(&config::scan_roots(&config), &env.home, &env.volumes_dir)
            .unwrap_or_else(|err| fail(err));
        let in_roots = roots.iter().any(|candidate| same_path(candidate, &root, &env.cwd));
        let others = roots.iter().filter(|candidate| !same_path(candidate, &root, &env.cwd)).cloned().collect();
        (roots, in_roots, others)
    } else {
        (vec![root.clone()], true, Vec::new())
    };

    // scanner._iter_targets, one walk per include glob
    let mut specs: Vec<WalkSpec> = Vec::new();
    let mut owners: Vec<Rule> = Vec::new();
    for rule in &selected {
        let bases: Vec<&String> = match rule.scope.as_str() {
            "home" if root_in_roots => vec![&root],
            "each_volume" => volume_roots.iter().collect(),
            _ => Vec::new(),
        };
        for base in bases {
            for pattern in &rule.include_globs {
                specs.push(WalkSpec {
                    base: base.clone(),
                    pattern: pattern.clone(),
                    kind: rule.kind.clone(),
                    excludes: rule.exclude_globs.clone(),
                    rule_id: rule.id.clone(),
                    min_age_days: rule.min_age_days as f64,
                    min_size_bytes: rule.min_size_bytes.max(0) as u64,
                });
                owners.push(rule.clone());
            }
        }
    }

    let now = request.now.unwrap_or_else(|| {
        SystemTime::now().duration_since(UNIX_EPOCH).map(|since| since.as_secs_f64()).unwrap_or(0.0)
    });
    let never_descend: Vec<String> = NEVER_DESCEND.iter().map(|name| (*name).to_owned()).collect();
    let scanned = native_scan(&env, &extra_protected, &never_descend, request.setup.threads, now, &specs);
    Scan { roots, scanned, owners }
}

pub fn scan_json_main(input: &str) {
    let started = Instant::now();
    let request: NativeRequest =
        serde_json::from_str(input).unwrap_or_else(|err| fail(format!("bad scan-json request: {err}")));
    let Scan { roots, scanned, owners } = scan(&request);

    // ScanResult.to_dict
    let mut categories: Vec<(&str, u64, u64)> = Vec::new(); // in order of first appearance
    for hit in &scanned.candidates {
        let category = owners[hit.walk].category.as_str();
        match categories.iter_mut().find(|(name, _, _)| *name == category) {
            Some((_, count, size)) => {
                *count += 1;
                *size += hit.size;
            }
            None => categories.push((category, 1, hit.size)),
        }
    }
    categories.sort_by(|a, b| b.2.cmp(&a.2)); // stable, like sorted(..., reverse=True)
    let errors: Vec<J> = scanned
        .read_errors
        .iter()
        .take(MAX_ERRORS)
        .map(|(walk, path, errno)| {
            let why = if *errno == 0 { "unknown error".to_owned() } else { strerror(*errno) };
            J::Str(format!("{}: cannot read {path}: {why}", owners[*walk].id))
        })
        .collect();
    let report = J::dict([
        ("scan_roots", J::strings(&roots)),
        ("total_size_bytes", J::UInt(scanned.candidates.iter().map(|hit| hit.size).sum())),
        ("candidate_count", J::UInt(scanned.candidates.len() as u64)),
        ("overlaps_dropped", J::UInt(scanned.overlaps_dropped as u64)),
        ("duration_seconds", J::Float((started.elapsed().as_secs_f64() * 1000.0).round() / 1000.0)),
        ("errors", J::List(errors)),
        (
            "categories",
            J::List(
                categories
                    .into_iter()
                    .map(|(category, count, size)| {
                        J::dict([("category", J::str(category)), ("count", J::UInt(count)), ("size_bytes", J::UInt(size))])
                    })
                    .collect(),
            ),
        ),
        (
            "candidates",
            J::List(
                scanned
                    .candidates
                    .iter()
                    .map(|hit| candidate_json(hit, &owners[hit.walk]))
                    .collect(),
            ),
        ),
    ]);
    println!("{}", dumps(&report));
}

/// `fclean config show --json`.
pub fn config_json_main(input: &str) {
    let request: NativeRequest =
        serde_json::from_str(input).unwrap_or_else(|err| fail(format!("bad config-json request: {err}")));
    let Loaded { paths, config, rules, .. } = load(&request.setup);
    let listed = rules
        .iter()
        .map(|rule| {
            let mut pairs = rule.to_json();
            pairs.push(("enabled".to_owned(), J::Bool(rules::is_enabled(&config, rule))));
            J::Dict(pairs)
        })
        .collect();
    let report = J::dict([
        ("config_file", J::str(&paths.config_file)),
        ("config", config::to_json(&toml::Value::Table(config))),
        ("rules", J::List(listed)),
    ]);
    println!("{}", dumps(&report));
}

/// Test hook for the writer itself: `{"strings": [...], "float_bits": [...]}`
/// in, the same values out through `dumps`. Floats travel as their bits so
/// that no parser stands between the test and the formatter.
pub fn pyjson_main(input: &str) {
    #[derive(Deserialize)]
    struct Values {
        strings: Vec<String>,
        float_bits: Vec<u64>,
    }
    let values: Values = serde_json::from_str(input).unwrap_or_else(|err| fail(format!("bad pyjson request: {err}")));
    let report = J::dict([
        ("strings", J::strings(&values.strings)),
        ("floats", J::List(values.float_bits.iter().map(|bits| J::Float(f64::from_bits(*bits))).collect())),
    ]);
    println!("{}", dumps(&report));
}
