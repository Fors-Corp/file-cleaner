//! `leftovers.find_app_leftovers`, `leftovers.find_installer_cleanup` and what
//! `fclean leftovers --json` prints. Finding only: `--apply` is not ported.
//!
//! Both detectors cross-reference what is installed, which no glob can
//! express. They are heuristics, and are ported as they are — including the
//! order of what they find, which is the order the folders list in.

use std::collections::HashSet;
use std::fs;
use std::time::{SystemTime, UNIX_EPOCH};

use rayon::prelude::*;
use serde::Deserialize;

use crate::pyjson::{dumps, J};
use crate::pypath::{normalise, splitext};
use crate::report::{load, Loaded, Setup};
use crate::{config, dir_stats, fail, mtime_nanos, read_dir, safety, st_mtime, start_pool, Deny};

const LIBRARY_SUBDIRS: [&str; 7] =
    ["Application Support", "Caches", "Preferences", "Logs", "Saved Application State", "Containers", "HTTPStorages"];
const INSTALLER_EXTENSIONS: [&str; 3] = [".dmg", ".pkg", ".zip"];
const MIN_AGE_DAYS: f64 = 30.0;

#[derive(Deserialize)]
struct Request {
    #[serde(flatten)]
    setup: Setup,
    /// `fclean leftovers --kind apps|installers|all`.
    #[serde(default = "default_kind")]
    kind: String,
    /// Python looks these up once, when `leftovers` is imported.
    applications_dirs: Option<Vec<String>>,
    now: Option<f64>,
}

fn default_kind() -> String {
    "all".to_owned()
}

pub struct Candidate {
    pub path: String,
    pub size: u64,
    pub is_dir: bool,
    pub mtime: f64,
    pub rule_id: &'static str,
    pub category: &'static str,
    pub risk: &'static str,
}

impl Candidate {
    /// `Candidate.to_dict`.
    pub fn to_json(&self) -> J {
        J::dict([
            ("path", J::str(&self.path)),
            ("size_bytes", J::UInt(self.size)),
            ("is_dir", J::Bool(self.is_dir)),
            ("mtime", J::Float(self.mtime)),
            ("rule_id", J::str(self.rule_id)),
            ("category", J::str(self.category)),
            ("risk", J::str(self.risk)),
        ])
    }
}

pub struct Installed {
    bundle_ids: HashSet<String>,
    names: HashSet<String>,
}

/// The names in `dir`, in the order it lists them. A name that is not
/// Unicode cannot be one Python would have printed, and is left out.
fn names_in(dir: &str) -> Option<Vec<String>> {
    Some(read_dir(dir).ok()?.into_iter().filter_map(|entry| entry.file_name().into_string().ok()).collect())
}

/// `installed_apps`: every `.app` in the applications folders, by bundle
/// identifier and by name. An `Info.plist` that cannot be read names nothing.
pub fn installed_apps(applications_dirs: &[String]) -> Installed {
    let mut installed = Installed { bundle_ids: HashSet::new(), names: HashSet::new() };
    for dir in applications_dirs {
        for name in names_in(dir).unwrap_or_default() {
            let (stem, suffix) = splitext(&name);
            if suffix != ".app" {
                continue;
            }
            installed.names.insert(stem.to_owned());
            let Ok(info) = plist::Value::from_file(format!("{dir}/{name}/Contents/Info.plist")) else { continue };
            let bundle_id = info.as_dictionary().and_then(|info| info.get("CFBundleIdentifier")).and_then(|id| id.as_string());
            if let Some(bundle_id) = bundle_id {
                installed.bundle_ids.insert(bundle_id.to_owned());
            }
        }
    }
    installed
}

impl Installed {
    /// `_looks_installed`. Many Library folders are named after the bundle
    /// identifier with something added ("com.example.app.savedState").
    fn owns(&self, name: &str) -> bool {
        self.bundle_ids.contains(name) || self.names.contains(name) || self.bundle_ids.iter().any(|id| name.starts_with(id.as_str()))
    }
}

/// Folders and files under `~/Library/{Application Support,Caches,...}` that
/// no installed app accounts for, untouched for a month. Opt-in, high risk.
pub fn find_app_leftovers(home: &str, installed: &Installed, index: &Deny, cwd: &str, now: f64) -> Vec<Candidate> {
    let mut orphans: Vec<(String, fs::Metadata)> = Vec::new();
    for subdir in LIBRARY_SUBDIRS {
        let base = format!("{home}/Library/{subdir}");
        for name in names_in(&base).unwrap_or_default() {
            let path = format!("{base}/{name}");
            let meta = fs::symlink_metadata(&path);
            if meta.as_ref().is_ok_and(|meta| meta.file_type().is_symlink()) || safety::is_protected(&path, index, cwd) {
                continue;
            }
            if installed.owns(&name) {
                continue;
            }
            if let Ok(meta) = meta {
                orphans.push((path, meta));
            }
        }
    }

    // `scanner.dir_stats_many`: sized together, across every core. Python
    // asks the helper only when there is more than one folder, and sizes a
    // lone one itself — reading the newest time its own way (`st_mtime`).
    let folders: Vec<&(String, fs::Metadata)> = orphans.iter().filter(|(_, meta)| meta.is_dir()).collect();
    let by_helper = folders.len() > 1;
    let mut sized = folders.par_iter().map(|(path, meta)| dir_stats(path, mtime_nanos(meta))).collect::<Vec<_>>().into_iter();

    let mut candidates = Vec::new();
    for (path, meta) in &orphans {
        let own = st_mtime(mtime_nanos(meta));
        let (size, mtime) = match meta.is_dir().then(|| sized.next()).flatten() {
            Some((size, newest)) => (size, own.max(if by_helper { newest as f64 / 1e9 } else { st_mtime(newest) })),
            None => (meta.len(), own),
        };
        if (now - mtime) / 86400.0 < MIN_AGE_DAYS {
            continue;
        }
        candidates.push(Candidate {
            path: path.clone(),
            size,
            is_dir: meta.is_dir(),
            mtime,
            rule_id: "app_leftovers",
            category: "App leftovers (opt-in)",
            risk: "high",
        });
    }
    candidates
}

/// `.dmg`/`.pkg`/`.zip` files in Downloads whose product is already there:
/// an installed app of that name, or a folder of that name next to the
/// archive. Opt-in, medium risk.
pub fn find_installer_cleanup(downloads: &str, installed: &Installed, index: &Deny, cwd: &str) -> Vec<Candidate> {
    let mut candidates = Vec::new();
    for name in names_in(downloads).unwrap_or_default() {
        let path = format!("{downloads}/{name}");
        if !fs::symlink_metadata(&path).is_ok_and(|meta| meta.is_file()) {
            continue; // a symlink, or not a file
        }
        let (stem, suffix) = splitext(&name);
        if !INSTALLER_EXTENSIONS.contains(&suffix.to_lowercase().as_str()) || safety::is_protected(&path, index, cwd) {
            continue;
        }
        let wanted = stem.to_lowercase();
        let already_installed = installed.names.contains(stem)
            || installed.bundle_ids.iter().any(|id| id.rsplit('.').next().is_some_and(|last| last.to_lowercase() == wanted));
        let already_extracted = fs::metadata(format!("{downloads}/{stem}")).is_ok_and(|meta| meta.is_dir());
        if !(already_installed || already_extracted) {
            continue;
        }
        let Ok(meta) = fs::metadata(&path) else { continue };
        candidates.push(Candidate {
            path,
            size: meta.len(),
            is_dir: false,
            mtime: st_mtime(mtime_nanos(&meta)),
            rule_id: "installer_cleanup",
            category: "Installer cleanup (opt-in)",
            risk: "medium",
        });
    }
    candidates
}

pub fn main(input: &str) {
    let request: Request =
        serde_json::from_str(input).unwrap_or_else(|err| fail(format!("bad leftovers-json request: {err}")));
    if !["apps", "installers", "all"].contains(&request.kind.as_str()) {
        fail(format!("--kind must be 'apps', 'installers', or 'all', got {}", crate::rules::repr(&request.kind)));
    }
    let Loaded { env, paths, config, .. } = load(&request.setup);
    let home = normalise(&env.home);
    let extra_protected = config::protected_paths(&config, &paths, &env.home).unwrap_or_else(|err| fail(err));
    let index = safety::build_index(&env, &extra_protected);
    let applications_dirs =
        request.applications_dirs.unwrap_or_else(|| vec!["/Applications".to_owned(), format!("{home}/Applications")]);
    let now = request
        .now
        .unwrap_or_else(|| SystemTime::now().duration_since(UNIX_EPOCH).map(|since| since.as_secs_f64()).unwrap_or(0.0));
    start_pool(request.setup.threads);

    let installed = installed_apps(&applications_dirs);
    let mut candidates = Vec::new();
    if request.kind != "installers" {
        candidates.extend(find_app_leftovers(&home, &installed, &index, &env.cwd, now));
    }
    if request.kind != "apps" {
        candidates.extend(find_installer_cleanup(&format!("{home}/Downloads"), &installed, &index, &env.cwd));
    }
    let report = J::dict([
        ("candidates", J::List(candidates.iter().map(Candidate::to_json).collect())),
        ("total_size_bytes", J::UInt(candidates.iter().map(|candidate| candidate.size).sum())),
    ]);
    println!("{}", dumps(&report));
}
