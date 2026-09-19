//! `largefiles.find_large_files` and what `fclean large-files --json` prints.

use serde::Deserialize;

use crate::filewalk::{self, FileEntry};
use crate::pyjson::{dumps, J};
use crate::report::{load, Loaded, Setup};
use crate::{config, fail, safety, start_pool};

#[derive(Deserialize)]
struct Request {
    #[serde(flatten)]
    setup: Setup,
    /// `fclean large-files [PATHS]... --top N --min-size BYTES`.
    paths: Option<Vec<String>>,
    #[serde(default = "default_top")]
    top: i64,
    #[serde(default)]
    min_size: i64,
}

fn default_top() -> i64 {
    30
}

/// The `top` largest, biggest first. Python keeps a bounded heap of
/// `(size, str(path), mtime)` tuples and sorts it in reverse; the same
/// tuples, in the same order, without the heap.
pub fn find_large_files(mut files: Vec<FileEntry>, top: usize) -> Vec<FileEntry> {
    files.sort_by(|a, b| (b.size, &b.path).cmp(&(a.size, &a.path)).then(b.mtime.total_cmp(&a.mtime)));
    files.truncate(top);
    files
}

pub fn main(input: &str) {
    let request: Request =
        serde_json::from_str(input).unwrap_or_else(|err| fail(format!("bad large-files-json request: {err}")));
    // Python's heap is indexed before it is known to hold anything: `--top 0`
    // is an IndexError there as soon as one file is found. Refused by name.
    if request.top < 1 {
        fail("--top must be at least 1".to_owned());
    }
    let Loaded { env, paths, config, .. } = load(&request.setup);
    let roots = filewalk::command_roots(request.paths.as_deref(), &env.home).unwrap_or_else(|err| fail(err));
    let extra_protected = config::protected_paths(&config, &paths, &env.home).unwrap_or_else(|err| fail(err));
    let index = safety::build_index(&env, &extra_protected);
    start_pool(request.setup.threads);

    let files = filewalk::walk_unique_files(&env, &index, &roots, request.min_size.max(0) as u64);
    let largest = find_large_files(files, request.top as usize);
    let report = J::dict([(
        "files",
        J::List(
            largest
                .iter()
                .map(|file| {
                    J::dict([
                        ("path", J::str(&file.path)),
                        ("size_bytes", J::UInt(file.size)),
                        ("mtime", J::Float(file.mtime)),
                    ])
                })
                .collect(),
        ),
    )]);
    println!("{}", dumps(&report));
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(path: &str, size: u64, mtime: f64) -> FileEntry {
        FileEntry { path: path.to_owned(), size, mtime }
    }

    #[test]
    fn biggest_first_then_by_path_downwards() {
        let files = vec![entry("/a", 5, 1.0), entry("/c", 9, 1.0), entry("/b", 5, 2.0), entry("/d", 1, 1.0)];
        let names: Vec<String> = find_large_files(files, 3).into_iter().map(|file| file.path).collect();
        assert_eq!(names, ["/c", "/b", "/a"]); // sorted(reverse=True) on (size, path, mtime)
    }
}
