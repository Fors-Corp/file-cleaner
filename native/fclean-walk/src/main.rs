//! fclean-walk: the parallel directory walk behind `fclean scan`.
//!
//! This is an *accelerator*, not an authority. It is a port of
//! `scanner._walk_rule_pattern` / `scanner.dir_stats` whose one real
//! advantage is that directory listings fan out across every core, which
//! the Python walk cannot do under the GIL. The Python scanner stays the
//! reference implementation and the fallback, and it re-checks every path
//! reported here against the authoritative deny-list before using it — so
//! nothing here is trusted for safety, only for speed.
//!
//! Protocol: one JSON request on stdin, newline-delimited JSON on stdout.
//!   match     {"m": walk, "p": path, "d": is_dir, "s": bytes, "t": mtime}
//!   error     {"e": walk, "p": dir, "errno": n}
//!   progress  {"n": dirs_done, "w": walk, "r": rel}
//!   end       {"done": dirs_total}
//! `fclean-walk key` instead maps a JSON array of strings to their deny-list
//! comparison keys (used to prove the key matches Python's `safety._key`).

use std::fs;
use std::io::{self, BufWriter, Read, Write};
use std::os::unix::fs::MetadataExt;
use std::path::PathBuf;
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::sync::Mutex;

use regex::Regex;
use serde::Deserialize;
use serde_json::json;
use unicode_normalization::UnicodeNormalization;

const PROGRESS_EVERY_DIRS: u64 = 1024;

// ------------------------------------------------------------------ request

#[derive(Deserialize)]
struct Request {
    #[serde(default)]
    threads: usize,
    deny_home: String,
    deny_prefixes: Vec<String>,
    #[serde(default)]
    never_descend: Vec<String>,
    walks: Vec<WalkSpec>,
}

#[derive(Deserialize)]
struct WalkSpec {
    base: String,
    pattern: String,
    kind: String,
    #[serde(default)]
    excludes: Vec<String>,
}

// --------------------------------------------------------------------- glob
// A port of scanner.glob_to_regex / GlobMatcher.compile. Keep the two in step.

fn segment_to_regex(segment: &str) -> String {
    let chars: Vec<char> = segment.chars().collect();
    let mut out = String::new();
    let mut i = 0;
    while i < chars.len() {
        match chars[i] {
            '*' => out.push_str("[^/]*"),
            '?' => out.push_str("[^/]"),
            '[' => match chars[i + 1..].iter().position(|&c| c == ']') {
                None => out.push_str(&regex::escape("[")),
                Some(offset) => {
                    let end = i + 1 + offset;
                    let mut body: String = chars[i + 1..end].iter().collect();
                    if let Some(rest) = body.strip_prefix('!') {
                        body = format!("^{rest}");
                    }
                    out.push('[');
                    out.push_str(&body.replace('\\', "\\\\"));
                    out.push(']');
                    i = end;
                }
            },
            ch => out.push_str(&regex::escape(&ch.to_string())),
        }
        i += 1;
    }
    out
}

fn glob_to_regex(pattern: &str) -> String {
    let pattern = pattern.trim_matches('/');
    if pattern.is_empty() || pattern == "**" {
        return "^.*$".to_string();
    }
    let parts: Vec<&str> = pattern.split('/').collect();
    let mut regex = String::new();
    for (index, segment) in parts.iter().enumerate() {
        let last = index == parts.len() - 1;
        if *segment == "**" {
            if last {
                regex = format!("{}(?:/.*)?", regex.trim_end_matches('/'));
            } else {
                regex.push_str("(?:[^/]+/)*");
            }
            continue;
        }
        regex.push_str(&segment_to_regex(segment));
        if !last {
            regex.push('/');
        }
    }
    format!("^{regex}$")
}

struct Glob {
    regex: Regex,
    static_prefix: String,    // leading wildcard-free segments: the walk start dir
    max_depth: Option<usize>, // None for recursive (`**`) patterns
}

impl Glob {
    fn compile(pattern: &str) -> Result<Glob, regex::Error> {
        let parts: Vec<&str> = pattern.trim_matches('/').split('/').collect();
        let prefix: Vec<&str> = parts
            .iter()
            .take_while(|s| **s != "**" && !s.contains(['*', '?', '[']))
            .copied()
            .collect();
        Ok(Glob {
            regex: Regex::new(&glob_to_regex(pattern))?,
            static_prefix: prefix.join("/"),
            max_depth: if parts.contains(&"**") { None } else { Some(parts.len()) },
        })
    }
}

// --------------------------------------------------------------------- deny

/// `safety._key`: Unicode canonical caseless matching, NFD(casefold(NFD(s))).
fn key(s: &str) -> String {
    if s.is_ascii() {
        return s.to_ascii_lowercase();
    }
    let decomposed: String = s.nfd().collect();
    caseless::default_case_fold_str(&decomposed).nfd().collect()
}

/// `safety._DenyIndex`, received ready-made: Python owns how it is built.
struct Deny {
    home: String,
    prefixes: Vec<String>,
}

impl Deny {
    fn covers(&self, resolved: &str) -> bool {
        let mut probe = key(resolved);
        if probe == self.home {
            return true;
        }
        probe.push('/');
        self.prefixes.iter().any(|p| probe.starts_with(p.as_str()))
    }
}

// --------------------------------------------------------------------- bulk
// getattrlistbulk(2): name, type, size and mtime for a whole directory in one
// syscall, instead of one lstat per file. This is what makes sizing a
// node_modules tree cheap. macOS only; everything else (and any filesystem
// that refuses the call) uses the portable readdir + lstat path.

#[cfg(target_os = "macos")]
mod bulk {
    use std::ffi::{c_int, c_void, CString};
    use std::io;

    const ATTR_BIT_MAP_COUNT: u16 = 5;
    const ATTR_CMN_NAME: u32 = 0x0000_0001;
    const ATTR_CMN_OBJTYPE: u32 = 0x0000_0008;
    const ATTR_CMN_MODTIME: u32 = 0x0000_0400;
    const ATTR_CMN_ERROR: u32 = 0x2000_0000;
    const ATTR_CMN_RETURNED_ATTRS: u32 = 0x8000_0000;
    const ATTR_FILE_DATALENGTH: u32 = 0x0000_0200;
    pub const VDIR: u32 = 2;
    pub const VLNK: u32 = 5;

    #[repr(C)]
    struct AttrList {
        bitmapcount: u16,
        reserved: u16,
        commonattr: u32,
        volattr: u32,
        dirattr: u32,
        fileattr: u32,
        forkattr: u32,
    }

    extern "C" {
        fn getattrlistbulk(dirfd: c_int, list: *mut AttrList, buf: *mut c_void, size: usize, options: u64) -> c_int;
    }

    pub struct Entry<'a> {
        pub name: &'a str,
        pub vtype: u32,
        pub mtime_nanos: i64,
        pub size: u64,
    }

    struct Fd(c_int);
    impl Drop for Fd {
        fn drop(&mut self) {
            unsafe { libc::close(self.0) };
        }
    }

    /// Bounds-checked little reader over the kernel's packed reply.
    struct Cursor<'a> {
        buf: &'a [u8],
        at: usize,
    }
    impl Cursor<'_> {
        fn u32(&mut self) -> Option<u32> {
            let bytes = self.buf.get(self.at..self.at + 4)?;
            self.at += 4;
            Some(u32::from_ne_bytes(bytes.try_into().ok()?))
        }
        fn i64(&mut self) -> Option<i64> {
            let bytes = self.buf.get(self.at..self.at + 8)?;
            self.at += 8;
            Some(i64::from_ne_bytes(bytes.try_into().ok()?))
        }
    }

    fn parse<'a>(record: &'a [u8]) -> Option<Entry<'a>> {
        let mut c = Cursor { buf: record, at: 4 }; // past the record length
        let common = c.u32()?;
        let (_vol, _dir, file, _fork) = (c.u32()?, c.u32()?, c.u32()?, c.u32()?);
        if common & ATTR_CMN_ERROR != 0 && c.u32()? != 0 {
            return None; // the kernel could not stat this entry
        }
        let mut name = "";
        if common & ATTR_CMN_NAME != 0 {
            let reference_at = c.at;
            let (offset, length) = (c.u32()? as i32, c.u32()? as usize);
            let start = reference_at.checked_add_signed(offset as isize)?;
            let bytes = record.get(start..start + length.checked_sub(1)?)?; // drop the NUL
            name = std::str::from_utf8(bytes).ok()?;
        }
        let vtype = if common & ATTR_CMN_OBJTYPE != 0 { c.u32()? } else { 0 };
        let mtime_nanos = if common & ATTR_CMN_MODTIME != 0 {
            let (sec, nsec) = (c.i64()?, c.i64()?);
            sec.saturating_mul(1_000_000_000).saturating_add(nsec)
        } else {
            0
        };
        let size = if file & ATTR_FILE_DATALENGTH != 0 { c.i64()?.max(0) as u64 } else { 0 };
        Some(Entry { name, vtype, mtime_nanos, size })
    }

    /// Calls `each` for every entry of `dir`. `Err` means nothing was
    /// delivered, so the caller can safely redo the directory another way.
    pub fn list(dir: &str, mut each: impl FnMut(Entry<'_>)) -> io::Result<()> {
        let path = CString::new(dir).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
        let raw = unsafe { libc::open(path.as_ptr(), libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC) };
        if raw < 0 {
            return Err(io::Error::last_os_error());
        }
        let fd = Fd(raw);
        let mut list = AttrList {
            bitmapcount: ATTR_BIT_MAP_COUNT,
            reserved: 0,
            commonattr: ATTR_CMN_RETURNED_ATTRS | ATTR_CMN_ERROR | ATTR_CMN_NAME | ATTR_CMN_OBJTYPE | ATTR_CMN_MODTIME,
            volattr: 0,
            dirattr: 0,
            fileattr: ATTR_FILE_DATALENGTH,
            forkattr: 0,
        };
        let mut buf = vec![0u8; 256 * 1024];
        let mut delivered = false;
        loop {
            let count = unsafe { getattrlistbulk(fd.0, &mut list, buf.as_mut_ptr().cast(), buf.len(), 0) };
            if count < 0 {
                return if delivered { Ok(()) } else { Err(io::Error::last_os_error()) };
            }
            if count == 0 {
                return Ok(());
            }
            let mut at = 0usize;
            for _ in 0..count {
                let Some(header) = buf.get(at..at + 4) else { return Ok(()) };
                let length = u32::from_ne_bytes(header.try_into().expect("4 bytes")) as usize;
                let Some(record) = buf.get(at..at + length) else { return Ok(()) };
                if length < 4 {
                    return Ok(());
                }
                if let Some(entry) = parse(record) {
                    each(entry);
                }
                at += length;
            }
            delivered = true;
        }
    }
}

// --------------------------------------------------------------------- walk

struct Walk {
    index: usize,
    base: PathBuf,
    matcher: Glob,
    excludes: Vec<Regex>,
    kind: String,
}

impl Walk {
    fn excluded(&self, rel: &str) -> bool {
        self.excludes.iter().any(|r| r.is_match(rel))
    }
}

struct Ctx {
    deny: Deny,
    never_descend: Vec<String>,
    out: Mutex<BufWriter<io::Stdout>>,
    dirs: AtomicU64,
}

impl Ctx {
    fn send(&self, value: serde_json::Value, flush: bool) {
        let mut out = self.out.lock().unwrap_or_else(|e| e.into_inner());
        let ok = serde_json::to_writer(&mut *out, &value).is_ok()
            && out.write_all(b"\n").is_ok()
            && (!flush || out.flush().is_ok());
        if !ok {
            std::process::exit(1); // the reader went away; nothing left to do
        }
    }

    fn tick(&self, walk: &Walk, rel: &str) {
        let done = self.dirs.fetch_add(1, Ordering::Relaxed) + 1;
        if done % PROGRESS_EVERY_DIRS == 0 {
            self.send(json!({"n": done, "w": walk.index, "r": rel}), true);
        }
    }
}

fn join(dir: &str, name: &str) -> String {
    if dir.ends_with('/') {
        format!("{dir}{name}")
    } else {
        format!("{dir}/{name}")
    }
}

fn mtime_nanos(meta: &fs::Metadata) -> i64 {
    meta.mtime().saturating_mul(1_000_000_000).saturating_add(meta.mtime_nsec())
}

/// `scanner.dir_stats`: total size and newest mtime of everything below
/// `path`, never following symlinks — but spread across the pool.
fn dir_stats(path: &str, own_mtime: i64) -> (u64, i64) {
    fn visit<'s>(scope: &rayon::Scope<'s>, dir: String, size: &'s AtomicU64, newest: &'s AtomicI64) {
        #[cfg(target_os = "macos")]
        {
            let listed = bulk::list(&dir, |entry| match entry.vtype {
                bulk::VLNK => {}
                bulk::VDIR => {
                    let child = join(&dir, entry.name);
                    scope.spawn(move |s| visit(s, child, size, newest));
                }
                _ => {
                    size.fetch_add(entry.size, Ordering::Relaxed);
                    newest.fetch_max(entry.mtime_nanos, Ordering::Relaxed);
                }
            });
            if listed.is_ok() {
                return;
            }
        }
        let Ok(entries) = fs::read_dir(&dir) else { return };
        for entry in entries.flatten() {
            let Ok(file_type) = entry.file_type() else { continue };
            if file_type.is_symlink() {
                continue;
            }
            if file_type.is_dir() {
                if let Some(child) = entry.path().to_str().map(str::to_owned) {
                    scope.spawn(move |s| visit(s, child, size, newest));
                }
                continue;
            }
            let Ok(meta) = entry.metadata() else { continue }; // lstat: does not follow
            size.fetch_add(meta.len(), Ordering::Relaxed);
            newest.fetch_max(mtime_nanos(&meta), Ordering::Relaxed);
        }
    }

    let size = AtomicU64::new(0);
    let newest = AtomicI64::new(own_mtime);
    rayon::scope(|s| visit(s, path.to_owned(), &size, &newest));
    (size.load(Ordering::Relaxed), newest.load(Ordering::Relaxed))
}

fn emit(ctx: &Ctx, walk: &Walk, path: &str, is_dir: bool) {
    let Ok(meta) = fs::symlink_metadata(path) else { return };
    let own = mtime_nanos(&meta);
    let (size, newest) = if is_dir { dir_stats(path, own) } else { (meta.len(), own) };
    let mtime = newest.max(own) as f64 / 1e9;
    ctx.send(json!({"m": walk.index, "p": path, "d": is_dir, "s": size, "t": mtime}), false);
}

/// One traversal serves every walk in `active`. Walks that start in the same
/// directory (`**/node_modules` and `**/.DS_Store` both start at the scan
/// root) would otherwise each list the whole tree; here they share the
/// listings, while each still applies its own excludes, depth limit and
/// pattern — so the result is the same as running them separately.
fn visit<'s>(
    scope: &rayon::Scope<'s>,
    ctx: &'s Ctx,
    active: Vec<&'s Walk>,
    dir: String,
    resolved: String, // `dir` with every symlink resolved, no trailing slash ("" for the root)
    rel: String,
    depth: usize,
) {
    ctx.tick(active[0], &rel);
    let listing: io::Result<Vec<fs::DirEntry>> = fs::read_dir(&dir).and_then(|rd| rd.collect());
    let entries = match listing {
        Ok(entries) => entries,
        Err(err) => {
            for walk in &active {
                ctx.send(json!({"e": walk.index, "p": dir, "errno": err.raw_os_error().unwrap_or(0)}), false);
            }
            return;
        }
    };
    for entry in entries {
        let Ok(name) = entry.file_name().into_string() else { continue };
        let Ok(file_type) = entry.file_type() else { continue };
        if file_type.is_symlink() {
            continue;
        }
        // Symlinked entries are skipped above, so a child of a resolved
        // directory is itself resolved: no filesystem access needed here.
        let child_resolved = format!("{resolved}/{name}");
        if ctx.deny.covers(&child_resolved) {
            continue;
        }
        let child_rel = if rel.is_empty() { name.clone() } else { format!("{rel}/{name}") };
        let child = join(&dir, &name);
        let is_dir = file_type.is_dir();
        let mut descending: Vec<&'s Walk> = Vec::new();
        for &walk in &active {
            if walk.excluded(&child_rel) {
                continue;
            }
            let matched = walk.matcher.regex.is_match(&child_rel);
            if !is_dir {
                if matched && walk.kind == "file" {
                    emit(ctx, walk, &child, false);
                }
                continue;
            }
            if matched && walk.kind == "dir" {
                // Reported whole; this walk never descends into it.
                let child = child.clone();
                scope.spawn(move |_| emit(ctx, walk, &child, true));
                continue;
            }
            if ctx.never_descend.contains(&name) {
                continue;
            }
            if walk.matcher.max_depth.map_or(true, |max| depth + 1 < max) {
                descending.push(walk);
            }
        }
        if !descending.is_empty() {
            scope.spawn(move |s| visit(s, ctx, descending, child, child_resolved, child_rel, depth + 1));
        }
    }
}

/// `group`: walks with the same base and static prefix, i.e. the same start.
fn start<'s>(scope: &rayon::Scope<'s>, ctx: &'s Ctx, group: Vec<&'s Walk>) {
    let start_rel = group[0].matcher.static_prefix.clone();
    let base = &group[0].base;
    let start = if start_rel.is_empty() { base.clone() } else { base.join(&start_rel) };
    // A directory (following symlinks) that is not itself a symlink.
    if !fs::metadata(&start).map(|m| m.is_dir()).unwrap_or(false) {
        return;
    }
    if fs::symlink_metadata(&start).map(|m| m.file_type().is_symlink()).unwrap_or(true) {
        return;
    }
    let Ok(canonical) = fs::canonicalize(&start) else { return };
    let Some(canonical) = canonical.to_str() else { return };
    let active: Vec<&Walk> = if start_rel.is_empty() {
        group
    } else if ctx.deny.covers(canonical) {
        return;
    } else {
        group.into_iter().filter(|walk| !walk.excluded(&start_rel)).collect()
    };
    if active.is_empty() {
        return;
    }
    let Some(start) = start.to_str().map(str::to_owned) else { return };
    let resolved = canonical.trim_end_matches('/').to_owned();
    let depth = if start_rel.is_empty() { 0 } else { start_rel.split('/').count() };
    scope.spawn(move |s| visit(s, ctx, active, start, resolved, start_rel, depth));
}

// --------------------------------------------------------------------- main

fn fail(message: String) -> ! {
    eprintln!("fclean-walk: {message}");
    std::process::exit(2);
}

fn main() {
    let mut input = String::new();
    if let Err(err) = io::stdin().read_to_string(&mut input) {
        fail(format!("cannot read request: {err}"));
    }

    if std::env::args().nth(1).as_deref() == Some("key") {
        let strings: Vec<String> =
            serde_json::from_str(&input).unwrap_or_else(|err| fail(format!("bad key request: {err}")));
        let keys: Vec<String> = strings.iter().map(|s| key(s)).collect();
        println!("{}", serde_json::to_string(&keys).expect("strings serialise"));
        return;
    }

    let request: Request =
        serde_json::from_str(&input).unwrap_or_else(|err| fail(format!("bad request: {err}")));
    let mut walks = Vec::with_capacity(request.walks.len());
    for (index, spec) in request.walks.iter().enumerate() {
        if spec.kind != "dir" && spec.kind != "file" {
            fail(format!("walk {index}: unknown kind {:?}", spec.kind));
        }
        let matcher = Glob::compile(&spec.pattern)
            .unwrap_or_else(|err| fail(format!("walk {index}: pattern {:?}: {err}", spec.pattern)));
        let excludes = spec
            .excludes
            .iter()
            .map(|p| Glob::compile(p).map(|g| g.regex))
            .collect::<Result<Vec<_>, _>>()
            .unwrap_or_else(|err| fail(format!("walk {index}: exclude: {err}")));
        walks.push(Walk { index, base: PathBuf::from(&spec.base), matcher, excludes, kind: spec.kind.clone() });
    }

    let mut pool = rayon::ThreadPoolBuilder::new();
    if request.threads > 0 {
        pool = pool.num_threads(request.threads);
    }
    if let Err(err) = pool.build_global() {
        fail(format!("cannot start thread pool: {err}"));
    }

    let ctx = Ctx {
        deny: Deny { home: request.deny_home, prefixes: request.deny_prefixes },
        never_descend: request.never_descend,
        out: Mutex::new(BufWriter::new(io::stdout())),
        dirs: AtomicU64::new(0),
    };
    let mut groups: Vec<Vec<&Walk>> = Vec::new();
    for walk in &walks {
        let same_start = |g: &&mut Vec<&Walk>| {
            g[0].base == walk.base && g[0].matcher.static_prefix == walk.matcher.static_prefix
        };
        match groups.iter_mut().find(same_start) {
            Some(group) => group.push(walk),
            None => groups.push(vec![walk]),
        }
    }
    rayon::scope(|scope| {
        for group in groups {
            let ctx = &ctx;
            scope.spawn(move |s| start(s, ctx, group));
        }
    });
    ctx.send(json!({"done": ctx.dirs.load(Ordering::Relaxed)}), true);
}

// -------------------------------------------------------------------- tests

#[cfg(test)]
mod tests {
    use super::*;

    fn matches(pattern: &str, rel: &str) -> bool {
        Glob::compile(pattern).unwrap().regex.is_match(rel)
    }

    #[test]
    fn star_and_question_mark_never_cross_a_slash() {
        assert!(matches("*.log", "a.log"));
        assert!(!matches("*.log", "sub/a.log"));
        assert!(matches("a?c", "abc"));
        assert!(!matches("a?c", "a/c"));
    }

    #[test]
    fn double_star_matches_zero_or_more_directories() {
        assert!(matches("**/node_modules", "node_modules"));
        assert!(matches("**/node_modules", "a/b/node_modules"));
        assert!(!matches("**/node_modules", "a/node_modules/x"));
        assert!(matches("Library/Logs/**/*", "Library/Logs/x"));
        assert!(matches("Library/Logs/**/*", "Library/Logs/a/b/x"));
    }

    #[test]
    fn trailing_double_star_also_matches_the_directory_itself() {
        assert!(matches("Library/**", "Library"));
        assert!(matches("Library/**", "Library/a/b"));
        assert!(!matches("Library/**", "Libraryx"));
        assert!(matches("**", "anything/at/all"));
    }

    #[test]
    fn character_classes_and_literals() {
        assert!(matches("file[0-9].txt", "file7.txt"));
        assert!(!matches("file[!0-9].txt", "file7.txt"));
        assert!(matches("file[!0-9].txt", "fileA.txt"));
        assert!(matches("a[b", "a[b")); // an unclosed bracket is a literal
        assert!(matches("Application Support/x+y (1).z", "Application Support/x+y (1).z"));
        assert!(!matches("a.b", "aXb")); // '.' is a literal, not a wildcard
    }

    #[test]
    fn static_prefix_and_depth() {
        let g = Glob::compile("Library/Caches/*").unwrap();
        assert_eq!((g.static_prefix.as_str(), g.max_depth), ("Library/Caches", Some(3)));
        let g = Glob::compile("**/.DS_Store").unwrap();
        assert_eq!((g.static_prefix.as_str(), g.max_depth), ("", None));
        let g = Glob::compile("a/b*/c/**/d").unwrap();
        assert_eq!((g.static_prefix.as_str(), g.max_depth), ("a", None));
    }

    #[test]
    fn key_folds_case_and_normalisation() {
        assert_eq!(key("/System/Library"), "/system/library");
        assert_eq!(key("/Users/Jos\u{e9}"), key("/users/JOSE\u{301}"));
        assert_eq!(key("Stra\u{df}e"), key("STRASSE"));
    }

    #[test]
    fn deny_prefix_respects_the_path_separator() {
        let deny = Deny { home: "/users/me".into(), prefixes: vec!["/usr/".into(), "/users/me/.ssh/".into()] };
        assert!(deny.covers("/usr"));
        assert!(deny.covers("/USR/bin/x"));
        assert!(!deny.covers("/usr2/x"));
        assert!(deny.covers("/Users/Me")); // home itself ...
        assert!(!deny.covers("/Users/me/Documents")); // ... but not its children
        assert!(deny.covers("/Users/me/.SSH/id_rsa"));
    }
}
