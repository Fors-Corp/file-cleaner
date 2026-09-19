//! `duplicates.find_duplicates` and what `fclean duplicates --json` prints.
//! Finding only: nothing here deletes, and `--apply` is not ported.
//!
//! The same three-stage funnel as Python — size, then the SHA-256 of the
//! first 64 KiB, then of the whole file — so most files are ruled out without
//! being read through. The digests are printed, so they are Python's exactly.

use std::collections::{BTreeMap, HashSet};
use std::fs::File;
use std::io::Read;
use std::os::unix::fs::MetadataExt;

use rayon::prelude::*;
use serde::Deserialize;
use sha2::{Digest, Sha256};

use crate::filewalk;
use crate::pyjson::{dumps, J};
use crate::report::{load, Loaded, Setup};
use crate::{config, fail, pypath, safety, start_pool};

const PARTIAL_HASH_BYTES: u64 = 65536;
const FULL_HASH_CHUNK: usize = 1024 * 1024;
const DEFAULT_MAX_HASH_BYTES: i64 = 2_000_000_000;

#[derive(Deserialize)]
struct Request {
    #[serde(flatten)]
    setup: Setup,
    /// `fclean duplicates [PATHS]... --top N --min-size BYTES`.
    paths: Option<Vec<String>>,
    #[serde(default = "default_top")]
    top: i64,
    #[serde(default = "default_min_size")]
    min_size: i64,
}

fn default_top() -> i64 {
    30
}

fn default_min_size() -> i64 {
    4096
}

pub struct Group {
    pub sha256: String,
    pub size: u64,
    /// In `Path` order, one per physical file.
    pub paths: Vec<String>,
}

impl Group {
    pub fn wasted(&self) -> u64 {
        self.size * (self.paths.len() as u64).saturating_sub(1)
    }
}

type Hash = fn(&str) -> Option<String>;

/// `_is_on_disk`: false for a file macOS has evicted to iCloud, keeping a
/// placeholder (`SF_DATALESS`). Reading one downloads it — hours of that for
/// a home directory, onto the disk this tool exists to free — and a file with
/// no contents here wastes no space here.
fn is_on_disk(path: &str) -> bool {
    #[cfg(target_os = "macos")]
    {
        use std::os::macos::fs::MetadataExt as _;
        const SF_DATALESS: u32 = 0x4000_0000;
        if let Ok(meta) = std::fs::symlink_metadata(path) {
            return meta.st_flags() & SF_DATALESS == 0;
        }
    }
    let _ = path;
    true
}

/// A file that cannot be read is not a duplicate of anything.
fn partial_hash(path: &str) -> Option<String> {
    let mut head = Vec::with_capacity(PARTIAL_HASH_BYTES as usize);
    File::open(path).ok()?.take(PARTIAL_HASH_BYTES).read_to_end(&mut head).ok()?;
    Some(format!("{:x}", Sha256::digest(&head)))
}

fn full_hash(path: &str) -> Option<String> {
    let mut file = File::open(path).ok()?;
    let mut digest = Sha256::new();
    let mut chunk = vec![0u8; FULL_HASH_CHUNK];
    loop {
        match file.read(&mut chunk) {
            Ok(0) => return Some(format!("{:x}", digest.finalize())),
            Ok(read) => digest.update(&chunk[..read]),
            Err(err) if err.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => return None,
        }
    }
}

/// Hash every member of every bucket that still has two, and bucket again.
fn refine<K: Ord + Clone + Send + Sync>(buckets: BTreeMap<K, Vec<String>>, hash: Hash) -> BTreeMap<(K, String), Vec<String>> {
    let candidates: Vec<(K, String)> = buckets
        .into_iter()
        .filter(|(_, paths)| paths.len() >= 2)
        .flat_map(|(key, paths)| paths.into_iter().map(move |path| (key.clone(), path)))
        .collect();
    let hashed: Vec<Option<String>> = candidates.par_iter().map(|(_, path)| hash(path)).collect();
    let mut refined: BTreeMap<(K, String), Vec<String>> = BTreeMap::new();
    for ((key, path), digest) in candidates.into_iter().zip(hashed) {
        if let Some(digest) = digest {
            refined.entry((key, digest)).or_default().push(path);
        }
    }
    refined
}

/// `_distinct_files`: in `Path` order, one path per physical file. The walk
/// already visits each file once; "these are two different files" is what a
/// permanent delete rests on, and it is not left to the walk alone.
fn distinct_files(mut paths: Vec<String>) -> Vec<String> {
    paths.sort_by(|a, b| pypath::path_cmp(a, b));
    let mut seen = HashSet::new();
    // stat, not lstat: were one path a symlink to the other, following it is
    // what exposes the two as a single file.
    paths.retain(|path| std::fs::metadata(path).is_ok_and(|meta| seen.insert((meta.dev(), meta.ino()))));
    paths
}

/// `max_groups` of 0 is every group, as `if max_groups:` has it in Python.
pub fn find_duplicates(
    env: &safety::Environment,
    index: &crate::Deny,
    roots: &[String],
    min_size: u64,
    max_hash_bytes: i64,
    max_groups: usize,
) -> Vec<Group> {
    let files = filewalk::walk_unique_files(env, index, roots, min_size);
    // The authoritative check, per file, on top of the walk's pruning.
    let allowed: Vec<bool> =
        files.par_iter().map(|file| file.size >= min_size && !safety::is_protected(&file.path, index, &env.cwd)).collect();
    let mut by_size: BTreeMap<u64, Vec<String>> = BTreeMap::new();
    for (file, allowed) in files.into_iter().zip(allowed) {
        if allowed {
            by_size.entry(file.size).or_default().push(file.path);
        }
    }

    // Asked, as in Python, only of same-size candidates: the files about to be read.
    for paths in by_size.values_mut().filter(|paths| paths.len() >= 2) {
        paths.retain(|path| is_on_disk(path));
    }

    let mut by_partial = refine(by_size, partial_hash);
    by_partial.retain(|(size, _), _| i64::try_from(*size).is_ok_and(|size| size <= max_hash_bytes));
    // Keyed by size alone from here on, as in Python: two files of one size
    // and one digest are one group whatever their first 64 KiB hashed to —
    // which, the contents being equal, was the same thing anyway.
    let mut same_size: BTreeMap<u64, Vec<String>> = BTreeMap::new();
    for ((size, _), paths) in by_partial {
        if paths.len() >= 2 {
            same_size.entry(size).or_default().extend(paths);
        }
    }

    let mut groups: Vec<Group> = refine(same_size, full_hash)
        .into_iter()
        .map(|((size, sha256), paths)| Group { sha256, size, paths: distinct_files(paths) })
        .filter(|group| group.paths.len() > 1)
        .collect();
    groups.sort_by(|a, b| (b.wasted(), &b.sha256).cmp(&(a.wasted(), &a.sha256)));
    if max_groups > 0 {
        groups.truncate(max_groups);
    }
    groups
}

pub fn main(input: &str) {
    let request: Request =
        serde_json::from_str(input).unwrap_or_else(|err| fail(format!("bad duplicates-json request: {err}")));
    // Python slices with it: a negative `--top` silently drops groups from
    // the end of the list. Refused by name.
    let max_groups = usize::try_from(request.top).unwrap_or_else(|_| fail("--top must not be negative".to_owned()));
    let Loaded { env, paths, config, .. } = load(&request.setup);
    let roots = filewalk::command_roots(request.paths.as_deref(), &env.home).unwrap_or_else(|err| fail(err));
    let extra_protected = config::protected_paths(&config, &paths, &env.home).unwrap_or_else(|err| fail(err));
    let index = safety::build_index(&env, &extra_protected);
    let max_hash_bytes =
        config.get("hash_duplicates_max_bytes").and_then(toml::Value::as_integer).unwrap_or(DEFAULT_MAX_HASH_BYTES);
    start_pool(request.setup.threads);

    let groups = find_duplicates(&env, &index, &roots, request.min_size.max(0) as u64, max_hash_bytes, max_groups);
    let report = J::dict([
        (
            "groups",
            J::List(
                groups
                    .iter()
                    .map(|group| {
                        J::dict([
                            ("sha256", J::str(&group.sha256)),
                            ("size_bytes", J::UInt(group.size)),
                            ("wasted_bytes", J::UInt(group.wasted())),
                            ("copies", J::UInt(group.paths.len() as u64)),
                            ("paths", J::strings(&group.paths)),
                        ])
                    })
                    .collect(),
            ),
        ),
        ("total_wasted_bytes", J::UInt(groups.iter().map(Group::wasted).sum())),
    ]);
    println!("{}", dumps(&report));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn digests_are_the_ones_hashlib_gives() {
        let dir = std::env::temp_dir().join(format!("fclean-duplicates-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let empty = dir.join("empty");
        let abc = dir.join("abc");
        std::fs::write(&empty, b"").unwrap();
        std::fs::write(&abc, b"abc").unwrap();
        // hashlib.sha256(b"").hexdigest() and hashlib.sha256(b"abc").hexdigest()
        let of_nothing = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        let of_abc = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
        for hash in [partial_hash as Hash, full_hash as Hash] {
            assert_eq!(hash(empty.to_str().unwrap()).as_deref(), Some(of_nothing));
            assert_eq!(hash(abc.to_str().unwrap()).as_deref(), Some(of_abc));
            assert_eq!(hash(dir.join("missing").to_str().unwrap()), None);
        }
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
