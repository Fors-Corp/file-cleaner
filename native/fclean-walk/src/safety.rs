//! The deny-list: a port of `filecleaner/safety.py`, which remains the
//! reference (see docs/PORT.md). Conformance is `tests/safety_cases.json`.
//!
//! Every deny rule — absolute, per-volume, per-home, own code, user config —
//! is flattened into canonical-key prefixes; a path is protected if its
//! *resolved* form is at or below one of them, or is the home directory.

use std::collections::VecDeque;
use std::fs;

use crate::{key, Deny, IcloudDrive};

pub const ABSOLUTE_DENY_PATHS: &[&str] = &[
    "/System",
    "/usr",
    "/bin",
    "/sbin",
    "/etc",
    "/dev",
    "/private/etc",
    "/private/var/db",
    "/private/var/root",
    "/private/var/audit",
    "/private/var/vm",
    "/Applications",
    "/Library/Apple",
    "/Library/CoreServices",
    "/Library/Extensions",
    "/Library/Frameworks",
    "/Library/Keychains",
    "/Library/StagedExtensions",
    "/Library/SystemMigration",
];

/// Dangerous under any volume root (the boot volume or an external one).
pub const RELATIVE_DENY_SUBPATHS: &[&str] =
    &["System", "usr", "bin", "sbin", "private/var/db", "Library/Apple", "Library/CoreServices"];

pub const HOME_DENY_SUBPATHS: &[&str] = &[
    ".ssh",
    ".gnupg",
    "Library/Keychains",
    "Library/Mail",
    "Library/Messages",
    "Library/Photos",
    "Library/Mobile Documents", // except iCloud Drive, see ICLOUD_DRIVE_SUBPATH
    "Library/Accounts",
    "Library/Passes",
    "Library/Wallet",
];

/// The one child of `Library/Mobile Documents` that is not protected.
pub const ICLOUD_DRIVE_SUBPATH: &str = "Library/Mobile Documents/com~apple~CloudDocs";

/// More symlink hops than any real path has; past it, the path is a loop.
const MAX_SYMLINK_HOPS: usize = 40;

/// Where the things the deny-list is relative to live. Explicit rather than
/// read from the process environment, so a caller (or a test) decides.
pub struct Environment {
    pub home: String,
    pub volumes_dir: String,
    pub self_dirs: Vec<String>,
    pub cwd: String,
}

pub struct Unresolvable;

fn absolute(path: &str, cwd: &str) -> String {
    if path.starts_with('/') {
        path.to_owned()
    } else {
        format!("{}/{path}", cwd.trim_end_matches('/'))
    }
}

/// Python's `Path.resolve(strict=False)`: every symlink resolved, `..`
/// applied to the *resolved* parent, and a tail that does not exist kept as
/// typed. Case and Unicode normalisation are left alone, exactly as there —
/// folding them is the comparison key's job, not the resolver's.
pub fn resolve(path: &str, cwd: &str) -> Result<String, Unresolvable> {
    let mut pending: VecDeque<String> =
        absolute(path, cwd).split('/').filter(|c| !c.is_empty() && *c != ".").map(str::to_owned).collect();
    let mut resolved: Vec<String> = Vec::new();
    let mut hops = 0;
    while let Some(component) = pending.pop_front() {
        if component == ".." {
            resolved.pop();
            continue;
        }
        resolved.push(component);
        let so_far = format!("/{}", resolved.join("/"));
        let is_symlink = fs::symlink_metadata(&so_far).map(|m| m.file_type().is_symlink()).unwrap_or(false);
        if !is_symlink {
            continue; // an ordinary component, or one that does not exist: keep as typed
        }
        hops += 1;
        if hops > MAX_SYMLINK_HOPS {
            return Err(Unresolvable);
        }
        let target = fs::read_link(&so_far).map_err(|_| Unresolvable)?;
        let target = target.to_str().ok_or(Unresolvable)?;
        resolved.pop();
        if target.starts_with('/') {
            resolved.clear();
        }
        for part in target.split('/').rev().filter(|c| !c.is_empty() && *c != ".") {
            pending.push_front(part.to_owned());
        }
    }
    Ok(format!("/{}", resolved.join("/")))
}

/// `safety._resolve`: used for the deny directories themselves, where an
/// unresolvable one falls back to its absolute spelling rather than vanishing.
fn resolve_or_absolute(path: &str, cwd: &str) -> String {
    resolve(path, cwd).unwrap_or_else(|_| absolute(path, cwd))
}

fn under(root: &str, sub: &str) -> String {
    format!("{}/{sub}", root.trim_end_matches('/'))
}

/// `safety._volume_roots`: "/" plus whatever is mounted. The flag is set when
/// a mounted volume's name is not UTF-8: its deny prefixes cannot be written
/// as keys, so the caller must protect all of `volumes_dir` instead. (Python
/// carries such names as surrogate escapes; APFS refuses to create them.)
fn volume_roots(volumes_dir: &str) -> (Vec<String>, bool) {
    let mut roots = vec!["/".to_owned()];
    let mut unnameable = false;
    if let Ok(entries) = fs::read_dir(volumes_dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() || entry.file_type().map(|t| t.is_symlink()).unwrap_or(false) {
                match path.to_str() {
                    Some(path) => roots.push(path.to_owned()),
                    None => unnameable = true,
                }
            }
        }
    }
    (roots, unnameable)
}

/// `safety._build_deny_index`.
pub fn build_index(env: &Environment, extra_protected: &[String]) -> Deny {
    let mut denied: Vec<String> = Vec::new();
    for deny in ABSOLUTE_DENY_PATHS {
        denied.push((*deny).to_owned());
        denied.push(resolve_or_absolute(deny, &env.cwd));
    }
    let (roots, unnameable) = volume_roots(&env.volumes_dir);
    if unnameable {
        denied.push(resolve_or_absolute(&env.volumes_dir, &env.cwd));
    }
    for root in roots {
        let root = resolve_or_absolute(&root, &env.cwd);
        denied.extend(RELATIVE_DENY_SUBPATHS.iter().map(|sub| under(&root, sub)));
    }
    let home = resolve_or_absolute(&env.home, &env.cwd);
    denied.extend(HOME_DENY_SUBPATHS.iter().map(|sub| under(&home, sub)));
    denied.extend(env.self_dirs.iter().cloned());
    denied.extend(extra_protected.iter().map(|extra| resolve_or_absolute(extra, &env.cwd)));

    let as_prefix = |path: &String| format!("{}/", key(path).trim_end_matches('/'));
    let mut prefixes: Vec<String> = denied.iter().map(as_prefix).collect();
    prefixes.sort();
    prefixes.dedup();
    let containers = as_prefix(&under(&home, "Library/Mobile Documents"));
    let prefixes_without_mobile_documents: Vec<String> =
        prefixes.iter().filter(|p| **p != containers).cloned().collect();
    let icloud_drive =
        IcloudDrive { root: as_prefix(&under(&home, ICLOUD_DRIVE_SUBPATH)), prefixes_without_mobile_documents };
    Deny { home: key(&home), prefixes, icloud_drive: Some(icloud_drive) }
}

/// `safety.is_protected`: the authoritative check. Resolves first, so it is
/// safe on arbitrary input; a path that cannot be resolved cannot be shown
/// to be safe, and is protected.
pub fn is_protected(path: &str, index: &Deny, cwd: &str) -> bool {
    match resolve(path, cwd) {
        Ok(resolved) => index.covers(&resolved),
        Err(Unresolvable) => true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsStr;
    use std::os::unix::ffi::OsStrExt;
    use std::path::PathBuf;

    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("fclean-walk-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("scratch dir");
        dir.canonicalize().expect("scratch dir resolves")
    }

    fn env(volumes: &std::path::Path) -> Environment {
        Environment {
            home: "/nonexistent-home".to_owned(),
            volumes_dir: volumes.to_str().expect("utf-8 scratch path").to_owned(),
            self_dirs: Vec::new(),
            cwd: "/".to_owned(),
        }
    }

    #[test]
    fn a_volume_whose_name_cannot_be_a_key_protects_all_of_volumes() {
        let volumes = scratch("unnameable");
        fs::create_dir(volumes.join("Named")).expect("named volume");
        let bad = volumes.join(OsStr::from_bytes(b"bad\xff"));
        let expressible = fs::create_dir(&bad).is_ok(); // APFS says EILSEQ; most others allow it
        let index = build_index(&env(&volumes), &[]);
        let inside = |rest: &str| format!("{}/{rest}", volumes.display());

        assert!(is_protected(&inside("Named/System/x"), &index, "/"));
        assert_eq!(is_protected(&inside("Named/Documents/x"), &index, "/"), expressible);
        let _ = fs::remove_dir_all(&volumes);
    }

    #[test]
    fn what_cannot_be_resolved_is_protected() {
        let dir = scratch("loop");
        std::os::unix::fs::symlink(dir.join("b"), dir.join("a")).expect("a -> b");
        std::os::unix::fs::symlink(dir.join("a"), dir.join("b")).expect("b -> a");
        let index = build_index(&env(&dir), &[]);

        assert!(is_protected(dir.join("a/x").to_str().expect("utf-8"), &index, "/"));
        assert!(!is_protected(dir.join("plain/x").to_str().expect("utf-8"), &index, "/"));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn icloud_drive_is_open_but_other_icloud_containers_stay_protected() {
        let dir = scratch("icloud");
        let mut environment = env(&dir);
        environment.home = dir.to_str().expect("utf-8").to_owned();
        let index = build_index(&environment, &[]);
        let mobile = format!("{}/Library/Mobile Documents", dir.display());

        assert!(!is_protected(&format!("{mobile}/com~apple~CloudDocs/a/x"), &index, "/"));
        assert!(!is_protected(&format!("{mobile}/COM~APPLE~CLOUDDOCS/x"), &index, "/"));
        assert!(is_protected(&mobile, &index, "/"));
        assert!(is_protected(&format!("{mobile}/com~apple~Notes/x"), &index, "/"));
        assert!(is_protected(&format!("{mobile}/com~apple~CloudDocsx/x"), &index, "/"));
        let _ = fs::remove_dir_all(&dir);
    }
}
