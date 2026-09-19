//! `filewalk.walk_unique_files`, as Python runs it over the native walk:
//! every regular file under the roots, once per physical file — and then the
//! checks Python makes of whatever the walk reports (`_walk_natively`), which
//! are kept here although the walk is now in the same process. They are what
//! the byte-for-byte comparison with Python rests on, and they cost nothing.

use crate::{native_files, pypath, safety, Deny};

/// `[Path(p).expanduser() for p in paths] if paths else [Path.home()]`: the
/// roots of `duplicates` and `large-files`, as the command line gives them.
pub fn command_roots(paths: Option<&[String]>, home: &str) -> Result<Vec<String>, String> {
    match paths {
        Some(paths) if !paths.is_empty() => paths.iter().map(|path| pypath::expanduser(path, home)).collect(),
        _ => Ok(vec![pypath::normalise(home)]),
    }
}

pub struct FileEntry {
    /// As Python prints it: `str(Path(...))`.
    pub path: String,
    pub size: u64,
    pub mtime: f64,
}

/// `roots` are spelled as `str(Path)` spells them and are not resolved: a
/// file is reported under the root it was asked for. In order of path; the
/// Python walk promises no order, and nothing built on it depends on one.
pub fn walk_unique_files(env: &safety::Environment, index: &Deny, roots: &[String], min_size: u64) -> Vec<FileEntry> {
    // A root that cannot be resolved yields nothing the deny-list can be
    // asked about, so nothing is taken from it.
    let resolved: Vec<Option<String>> =
        roots.iter().map(|root| safety::resolve(root, &env.cwd).ok().map(|r| r.trim_end_matches('/').to_owned())).collect();
    let inside: Vec<String> = roots.iter().map(|root| format!("{}/", root.trim_end_matches('/'))).collect();

    let mut files = Vec::new();
    for found in native_files(index.clone(), roots, min_size) {
        let Some(rest) = found.path.strip_prefix(inside[found.root].as_str()) else { continue };
        let Some(resolved_root) = &resolved[found.root] else { continue };
        if found.size < min_size || index.covers(&format!("{resolved_root}/{rest}")) {
            continue;
        }
        files.push(FileEntry { path: pypath::normalise(&found.path), size: found.size, mtime: found.mtime() });
    }
    files
}
