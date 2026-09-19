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
//!
//! `fclean-walk files` is the walk behind `duplicates` and `large-files`
//! (a port of `filewalk.walk_unique_files`): every regular file under the
//! given roots, once per physical file, at least `min_size` bytes.
//!   file      {"f": path, "r": root index, "s": bytes, "t": mtime}
//!   end       {"done": files_reported}

use std::collections::{HashMap, HashSet};
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

mod config;
mod pyjson;
mod pypath;
mod report;
mod rules;
mod safety;
mod volumes;

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
pub struct WalkSpec {
    pub base: String,
    pub pattern: String,
    pub kind: String,
    #[serde(default)]
    pub excludes: Vec<String>,
    // Only the native `scan` uses these; the streaming walk leaves rule
    // thresholds to its caller.
    #[serde(default)]
    pub rule_id: String,
    #[serde(default)]
    pub min_age_days: f64,
    #[serde(default)]
    pub min_size_bytes: u64,
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
pub fn key(s: &str) -> String {
    if s.is_ascii() {
        return s.to_ascii_lowercase();
    }
    let decomposed: String = s.nfd().collect();
    caseless::default_case_fold_str(&decomposed).nfd().collect()
}

/// `safety._DenyIndex`: received ready-made from Python by the streaming
/// walk, built natively (`safety::build_index`) by `scan` and `protected`.
#[derive(Clone)]
pub struct Deny {
    home: String,
    prefixes: Vec<String>,
}

impl Deny {
    pub fn covers(&self, resolved: &str) -> bool {
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
    // Attributes come back packed in ascending bit order within each group
    // (ATTR_CMN_ERROR excepted: it follows the returned-attributes set).
    const ATTR_CMN_NAME: u32 = 0x0000_0001;
    const ATTR_CMN_DEVID: u32 = 0x0000_0002;
    const ATTR_CMN_OBJTYPE: u32 = 0x0000_0008;
    const ATTR_CMN_MODTIME: u32 = 0x0000_0400;
    const ATTR_CMN_FILEID: u32 = 0x0200_0000;
    const ATTR_CMN_ERROR: u32 = 0x2000_0000;
    const ATTR_CMN_RETURNED_ATTRS: u32 = 0x8000_0000;
    const ATTR_FILE_LINKCOUNT: u32 = 0x0000_0001;
    const ATTR_FILE_DATALENGTH: u32 = 0x0000_0200;
    pub const VREG: u32 = 1;
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
        pub dev: i64,
        pub ino: u64,
        pub nlink: u32,
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
        let dev = if common & ATTR_CMN_DEVID != 0 { c.u32()? as i32 as i64 } else { 0 };
        let vtype = if common & ATTR_CMN_OBJTYPE != 0 { c.u32()? } else { 0 };
        let mtime_nanos = if common & ATTR_CMN_MODTIME != 0 {
            let (sec, nsec) = (c.i64()?, c.i64()?);
            sec.saturating_mul(1_000_000_000).saturating_add(nsec)
        } else {
            0
        };
        let ino = if common & ATTR_CMN_FILEID != 0 { c.i64()? as u64 } else { 0 };
        let nlink = if file & ATTR_FILE_LINKCOUNT != 0 { c.u32()? } else { 0 };
        let size = if file & ATTR_FILE_DATALENGTH != 0 { c.i64()?.max(0) as u64 } else { 0 };
        Some(Entry { name, vtype, mtime_nanos, size, dev, ino, nlink })
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
            commonattr: ATTR_CMN_RETURNED_ATTRS
                | ATTR_CMN_ERROR
                | ATTR_CMN_NAME
                | ATTR_CMN_DEVID
                | ATTR_CMN_OBJTYPE
                | ATTR_CMN_MODTIME
                | ATTR_CMN_FILEID,
            volattr: 0,
            dirattr: 0,
            fileattr: ATTR_FILE_LINKCOUNT | ATTR_FILE_DATALENGTH,
            forkattr: 0,
        };
        let mut buf = vec![0u8; 256 * 1024];
        let mut delivered = false;
        let mut interruptions = 0;
        loop {
            let count = unsafe { getattrlistbulk(fd.0, &mut list, buf.as_mut_ptr().cast(), buf.len(), 0) };
            if count < 0 {
                let err = io::Error::last_os_error();
                if err.kind() == io::ErrorKind::Interrupted && interruptions < super::LISTING_RETRIES {
                    interruptions += 1; // nothing was consumed: ask again rather than stop short
                    continue;
                }
                return if delivered { Ok(()) } else { Err(err) };
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

// --------------------------------------------------------------- containers

/// `~/Library/Containers` and `~/Library/Group Containers` hold other apps'
/// sandboxes, and macOS checks every directory opened inside them. Now and
/// then that check hangs: the open blocks for five or six seconds and fails
/// with EINTR — at random, about once per pass single-threaded and dozens of
/// times with every core asking at once (12 s and more, against 1.7 s), and
/// the interrupted directories go unread. Asking again succeeds within a
/// millisecond, and the hang is an interruptible wait. So a call inside those
/// two places that has not returned in a quarter of a second is interrupted,
/// and everywhere an interrupted call is retried. (Listing them one at a time
/// as well was tried: with hangs this cheap it only costs parallelism — 2-6 s
/// for `~/Library` against 1.6-2.5 s.)
mod unstick {
    use std::sync::{Mutex, Once};
    use std::thread;
    use std::time::{Duration, Instant};

    const FIRST_PATIENCE: Duration = Duration::from_millis(250);
    /// Patience doubles with every poke, so a directory that really is slow
    /// gets 0.25 + 0.5 + 1 + 2 + 4 s of tries and then as long as it needs.
    const MAX_POKES: u32 = 5;
    const TICK: Duration = Duration::from_millis(50);

    struct Waiting {
        id: u64,
        thread: libc::pthread_t,
        poke_at: Instant,
        patience: Duration,
        pokes: u32,
    }

    static WAITING: Mutex<(u64, Vec<Waiting>)> = Mutex::new((0, Vec::new()));
    static STARTED: Once = Once::new();

    extern "C" fn wake(_signal: libc::c_int) {} // being delivered is the whole point

    fn start() {
        unsafe {
            let mut action: libc::sigaction = std::mem::zeroed();
            action.sa_sigaction = wake as extern "C" fn(libc::c_int) as usize;
            action.sa_flags = 0; // not SA_RESTART: the blocked call must fail with EINTR
            libc::sigemptyset(&mut action.sa_mask);
            if libc::sigaction(libc::SIGUSR2, &action, std::ptr::null_mut()) != 0 {
                return; // unhandled, SIGUSR2 would end the process: better to wait a hang out
            }
        }
        thread::spawn(|| loop {
            thread::sleep(TICK);
            let now = Instant::now();
            let mut waiting = WAITING.lock().unwrap_or_else(|e| e.into_inner());
            for entry in waiting.1.iter_mut().filter(|entry| entry.pokes < MAX_POKES && entry.poke_at <= now) {
                // Still registered, and registration is removed under this
                // lock: the thread is inside its listing and nowhere else.
                unsafe { libc::pthread_kill(entry.thread, libc::SIGUSR2) };
                entry.pokes += 1;
                entry.patience *= 2;
                entry.poke_at = now + entry.patience;
            }
        });
    }

    pub struct Watched(u64);

    /// Until the returned guard is dropped, this thread is interrupted
    /// whenever it sits in one system call for too long.
    pub fn watch() -> Watched {
        STARTED.call_once(start);
        let mut waiting = WAITING.lock().unwrap_or_else(|e| e.into_inner());
        waiting.0 += 1;
        let id = waiting.0;
        let thread = unsafe { libc::pthread_self() };
        waiting.1.push(Waiting { id, thread, poke_at: Instant::now() + FIRST_PATIENCE, patience: FIRST_PATIENCE, pokes: 0 });
        Watched(id)
    }

    impl Drop for Watched {
        fn drop(&mut self) {
            WAITING.lock().unwrap_or_else(|e| e.into_inner()).1.retain(|entry| entry.id != self.0);
        }
    }
}

/// More than `unstick` ever pokes, so the last tries are left alone.
const LISTING_RETRIES: usize = 8;

fn in_containers(path: &str) -> bool {
    path.contains("/Library/Containers") || path.contains("/Library/Group Containers")
}

/// Any one filesystem call on `path`, retried while it is interrupted. For a
/// listing, `attempt` must deliver nothing when it fails, so that running it
/// again cannot report an entry twice.
fn patiently<T>(path: &str, mut attempt: impl FnMut() -> io::Result<T>) -> io::Result<T> {
    let _watched = in_containers(path).then(unstick::watch);
    let mut interruptions = 0;
    loop {
        match attempt() {
            Err(err) if err.kind() == io::ErrorKind::Interrupted && interruptions < LISTING_RETRIES => {
                interruptions += 1;
            }
            outcome => return outcome,
        }
    }
}

/// The portable listing: an entry that cannot be read is left out. Reading
/// on after a failure is also what retries an interrupted read (the stream
/// does not advance past what it failed to deliver) — but a stream that does
/// nothing except fail is over.
fn read_dir(dir: &str) -> io::Result<Vec<fs::DirEntry>> {
    patiently(dir, || {
        let mut entries = Vec::new();
        let mut failures = 0;
        for entry in fs::read_dir(dir)? {
            match entry {
                Ok(entry) => {
                    entries.push(entry);
                    failures = 0;
                }
                Err(_) if failures < LISTING_RETRIES => failures += 1,
                Err(_) => break,
            }
        }
        Ok(entries)
    })
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

pub struct Hit {
    pub walk: usize,
    pub path: String,
    pub is_dir: bool,
    pub size: u64,
    pub mtime: f64,
}

/// Where matches go: streamed to the caller as they are found (the helper
/// protocol), or gathered for the native `scan` to finish the job itself.
#[derive(Default)]
struct Gathered {
    hits: Vec<Hit>,
    read_errors: Vec<(usize, String, i32)>,
}

struct Ctx {
    deny: Deny,
    never_descend: Vec<String>,
    out: Mutex<BufWriter<io::Stdout>>,
    dirs: AtomicU64,
    gather: Option<Mutex<Gathered>>,
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

    fn hit(&self, hit: Hit) {
        match &self.gather {
            Some(gathered) => gathered.lock().unwrap_or_else(|e| e.into_inner()).hits.push(hit),
            None => self.send(
                json!({"m": hit.walk, "p": hit.path, "d": hit.is_dir, "s": hit.size, "t": hit.mtime}),
                false,
            ),
        }
    }

    fn read_error(&self, walk: usize, dir: &str, errno: i32) {
        match &self.gather {
            Some(gathered) => {
                gathered.lock().unwrap_or_else(|e| e.into_inner()).read_errors.push((walk, dir.to_owned(), errno))
            }
            None => self.send(json!({"e": walk, "p": dir, "errno": errno}), false),
        }
    }

    fn tick(&self, walk: &Walk, rel: &str) {
        let done = self.dirs.fetch_add(1, Ordering::Relaxed) + 1;
        if self.gather.is_none() && done % PROGRESS_EVERY_DIRS == 0 {
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
            let listed = patiently(&dir, || {
                bulk::list(&dir, |entry| match entry.vtype {
                    bulk::VLNK => {}
                    bulk::VDIR => {
                        let child = join(&dir, entry.name);
                        scope.spawn(move |s| visit(s, child, size, newest));
                    }
                    _ => {
                        size.fetch_add(entry.size, Ordering::Relaxed);
                        newest.fetch_max(entry.mtime_nanos, Ordering::Relaxed);
                    }
                })
            });
            if listed.is_ok() {
                return;
            }
        }
        let Ok(entries) = read_dir(&dir) else { return };
        for entry in entries {
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
    let Ok(meta) = patiently(path, || fs::symlink_metadata(path)) else { return };
    let own = mtime_nanos(&meta);
    let (size, newest) = if is_dir { dir_stats(path, own) } else { (meta.len(), own) };
    let mtime = newest.max(own) as f64 / 1e9;
    ctx.hit(Hit { walk: walk.index, path: path.to_owned(), is_dir, size, mtime });
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
    let listed: io::Result<Vec<fs::DirEntry>> = patiently(&dir, || fs::read_dir(&dir).and_then(|rd| rd.collect()));
    let entries = match listed {
        Ok(entries) => entries,
        Err(err) => {
            for walk in &active {
                ctx.read_error(walk.index, &dir, err.raw_os_error().unwrap_or(0));
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

// -------------------------------------------------------------------- files
// A port of filewalk.walk_unique_files. One file can be reached by more than
// one path (overlapping roots, a root respelled in another case, a symlinked
// root, a second hard link) and must still be reported once. As there:
// a file with a single link lives in exactly one directory, so remembering
// the directories visited — by (st_dev, st_ino), never by path — is enough;
// only hard-linked files are remembered one by one.

#[derive(Deserialize)]
struct FilesRequest {
    #[serde(default)]
    threads: usize,
    deny_home: String,
    deny_prefixes: Vec<String>,
    roots: Vec<String>,
    #[serde(default)]
    min_size: u64,
}

struct Found {
    path: String,
    root: usize,
    size: u64,
    mtime_nanos: i64,
}

struct FilesCtx {
    deny: Deny,
    min_size: u64,
    out: Mutex<BufWriter<io::Stdout>>,
    reported: AtomicU64,
    seen_dirs: Mutex<HashSet<(u64, u64)>>,
    // Which name of a hard-linked file a parallel walk meets first is a
    // matter of timing, so they are held back and the smallest path wins.
    hard_links: Mutex<HashMap<(i64, u64), Found>>,
}

impl FilesCtx {
    fn report(&self, found: &Found) {
        if found.size < self.min_size {
            return;
        }
        self.reported.fetch_add(1, Ordering::Relaxed);
        let value = json!({"f": found.path, "r": found.root, "s": found.size, "t": found.mtime_nanos as f64 / 1e9});
        let mut out = self.out.lock().unwrap_or_else(|e| e.into_inner());
        if serde_json::to_writer(&mut *out, &value).is_err() || out.write_all(b"\n").is_err() {
            std::process::exit(1);
        }
    }

    fn regular_file(&self, found: Found, dev: i64, ino: u64, nlink: u32) {
        if nlink <= 1 {
            self.report(&found);
            return;
        }
        let mut links = self.hard_links.lock().unwrap_or_else(|e| e.into_inner());
        match links.get(&(dev, ino)) {
            Some(held) if held.path <= found.path => {}
            _ => {
                links.insert((dev, ino), found);
            }
        }
    }
}

fn files_visit<'s>(scope: &rayon::Scope<'s>, ctx: &'s FilesCtx, root: usize, dir: String, resolved: String) {
    // stat, not lstat: only a root can be a symlink, and it is to be followed.
    let Ok(meta) = patiently(&dir, || fs::metadata(&dir)) else { return };
    let first_visit = ctx.seen_dirs.lock().unwrap_or_else(|e| e.into_inner()).insert((meta.dev(), meta.ino()));
    if !first_visit {
        return;
    }
    let descend = |name: &str| {
        let child_resolved = format!("{resolved}/{name}");
        if !ctx.deny.covers(&child_resolved) {
            let child = join(&dir, name);
            scope.spawn(move |s| files_visit(s, ctx, root, child, child_resolved));
        }
    };

    #[cfg(target_os = "macos")]
    {
        let listed = patiently(&dir, || {
            bulk::list(&dir, |entry| match entry.vtype {
                bulk::VDIR => descend(entry.name),
                bulk::VREG => {
                    let found =
                        Found { path: join(&dir, entry.name), root, size: entry.size, mtime_nanos: entry.mtime_nanos };
                    ctx.regular_file(found, entry.dev, entry.ino, entry.nlink);
                }
                _ => {} // symlinks are never followed; FIFOs, sockets and devices are not files to compare
            })
        });
        if listed.is_ok() {
            return;
        }
    }
    let Ok(entries) = read_dir(&dir) else { return };
    for entry in entries {
        let Ok(name) = entry.file_name().into_string() else { continue };
        let Ok(file_type) = entry.file_type() else { continue };
        if file_type.is_symlink() {
            continue;
        }
        if file_type.is_dir() {
            descend(&name);
        } else if file_type.is_file() {
            let Ok(meta) = entry.metadata() else { continue }; // lstat
            let found = Found { path: join(&dir, &name), root, size: meta.len(), mtime_nanos: mtime_nanos(&meta) };
            ctx.regular_file(found, meta.dev() as i64, meta.ino(), meta.nlink() as u32);
        }
    }
}

fn files_main(input: &str) {
    let request: FilesRequest =
        serde_json::from_str(input).unwrap_or_else(|err| fail(format!("bad files request: {err}")));
    let mut pool = rayon::ThreadPoolBuilder::new();
    if request.threads > 0 {
        pool = pool.num_threads(request.threads);
    }
    if let Err(err) = pool.build_global() {
        fail(format!("cannot start thread pool: {err}"));
    }
    let ctx = FilesCtx {
        deny: Deny { home: request.deny_home, prefixes: request.deny_prefixes },
        min_size: request.min_size,
        out: Mutex::new(BufWriter::with_capacity(1 << 20, io::stdout())),
        reported: AtomicU64::new(0),
        seen_dirs: Mutex::new(HashSet::new()),
        hard_links: Mutex::new(HashMap::new()),
    };
    // One root at a time, each walked in parallel: when two roots reach the
    // same directory, the earlier root keeps it, as in the Python walk.
    for (index, root) in request.roots.iter().enumerate() {
        let Ok(canonical) = fs::canonicalize(root) else { continue };
        let Some(resolved) = canonical.to_str().map(|s| s.trim_end_matches('/').to_owned()) else { continue };
        let ctx = &ctx;
        rayon::scope(|scope| files_visit(scope, ctx, index, root.clone(), resolved));
    }
    let mut held: Vec<Found> = ctx.hard_links.lock().unwrap_or_else(|e| e.into_inner()).drain().map(|(_, f)| f).collect();
    held.sort_by(|a, b| a.path.cmp(&b.path));
    for found in &held {
        ctx.report(found);
    }
    let value = json!({"done": ctx.reported.load(Ordering::Relaxed)});
    let mut out = ctx.out.lock().unwrap_or_else(|e| e.into_inner());
    if serde_json::to_writer(&mut *out, &value).is_err() || out.write_all(b"\n").is_err() || out.flush().is_err() {
        std::process::exit(1);
    }
}

// --------------------------------------------------------------------- main

#[derive(Deserialize)]
struct SizesRequest {
    dirs: Vec<String>,
    #[serde(default)]
    threads: usize,
}

/// `sizes` mode: `scanner.dir_stats` for many directories at once. One line
/// per directory, by index, in whatever order they finish. A directory that
/// cannot be read contributes nothing, as in Python.
fn sizes_main(input: &str) {
    use rayon::prelude::*;
    let request: SizesRequest =
        serde_json::from_str(input).unwrap_or_else(|err| fail(format!("bad sizes request: {err}")));
    start_pool(request.threads);
    let out = Mutex::new(BufWriter::new(io::stdout()));
    request.dirs.par_iter().enumerate().for_each(|(index, dir)| {
        let own = fs::symlink_metadata(dir).map(|meta| mtime_nanos(&meta)).unwrap_or(0);
        let (size, newest) = dir_stats(dir, own);
        let line = json!({"i": index, "s": size, "t": newest as f64 / 1e9});
        let mut out = out.lock().unwrap_or_else(|e| e.into_inner());
        let _ = writeln!(out, "{line}");
    });
    let mut out = out.lock().unwrap_or_else(|e| e.into_inner());
    let _ = writeln!(out, "{}", json!({"done": request.dirs.len()}));
    let _ = out.flush();
}

pub fn fail(message: String) -> ! {
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

    if std::env::args().nth(1).as_deref() == Some("files") {
        files_main(&input);
        return;
    }

    match std::env::args().nth(1).as_deref() {
        Some("deny-lists") => return deny_lists_main(),
        Some("protected") => return protected_main(&input),
        Some("scan") => return scan_main(&input),
        Some("sizes") => return sizes_main(&input),
        Some("scan-json") => return report::scan_json_main(&input),
        Some("config-json") => return report::config_json_main(&input),
        Some("pyjson") => return report::pyjson_main(&input),
        _ => {}
    }

    let request: Request =
        serde_json::from_str(&input).unwrap_or_else(|err| fail(format!("bad request: {err}")));
    let walks = compile_walks(&request.walks);
    start_pool(request.threads);
    let ctx = Ctx {
        deny: Deny { home: request.deny_home, prefixes: request.deny_prefixes },
        never_descend: request.never_descend,
        out: Mutex::new(BufWriter::new(io::stdout())),
        dirs: AtomicU64::new(0),
        gather: None,
    };
    run_walks(&ctx, &walks);
    ctx.send(json!({"done": ctx.dirs.load(Ordering::Relaxed)}), true);
}

fn compile_walks(specs: &[WalkSpec]) -> Vec<Walk> {
    let mut walks = Vec::with_capacity(specs.len());
    for (index, spec) in specs.iter().enumerate() {
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
    walks
}

fn start_pool(threads: usize) {
    let mut pool = rayon::ThreadPoolBuilder::new();
    if threads > 0 {
        pool = pool.num_threads(threads);
    }
    if let Err(err) = pool.build_global() {
        fail(format!("cannot start thread pool: {err}"));
    }
}

fn run_walks(ctx: &Ctx, walks: &[Walk]) {
    let mut groups: Vec<Vec<&Walk>> = Vec::new();
    for walk in walks {
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
            scope.spawn(move |s| start(s, ctx, group));
        }
    });
}

// ------------------------------------------------- the port (docs/PORT.md)
// Phase 1: the deny-list and the scan, with no Python in the loop. The
// streaming protocol above is what production uses; these exist so the port
// can be proven against the Python reference before anything depends on it.

#[derive(Deserialize)]
struct EnvSpec {
    home: String,
    #[serde(default = "default_volumes_dir")]
    volumes_dir: String,
    #[serde(default)]
    self_dirs: Vec<String>,
}

fn default_volumes_dir() -> String {
    "/Volumes".to_owned()
}

impl EnvSpec {
    fn environment(&self) -> safety::Environment {
        let cwd = std::env::current_dir().ok().and_then(|p| p.to_str().map(str::to_owned)).unwrap_or_else(|| "/".into());
        safety::Environment {
            home: self.home.clone(),
            volumes_dir: self.volumes_dir.clone(),
            self_dirs: self.self_dirs.clone(),
            cwd,
        }
    }
}

fn deny_lists_main() {
    let lists = json!({
        "absolute": safety::ABSOLUTE_DENY_PATHS,
        "relative": safety::RELATIVE_DENY_SUBPATHS,
        "home": safety::HOME_DENY_SUBPATHS,
    });
    println!("{lists}");
}

#[derive(Deserialize)]
struct ProtectedQuery {
    path: String,
    #[serde(default)]
    extra_protected: Vec<String>,
}

#[derive(Deserialize)]
struct ProtectedRequest {
    #[serde(flatten)]
    env: EnvSpec,
    queries: Vec<ProtectedQuery>,
}

/// `safety.is_protected` for a batch of paths -> a JSON array of verdicts.
fn protected_main(input: &str) {
    let request: ProtectedRequest =
        serde_json::from_str(input).unwrap_or_else(|err| fail(format!("bad protected request: {err}")));
    let env = request.env.environment();
    let mut indexes: HashMap<Vec<String>, Deny> = HashMap::new();
    let verdicts: Vec<bool> = request
        .queries
        .iter()
        .map(|query| {
            let index = indexes
                .entry(query.extra_protected.clone())
                .or_insert_with(|| safety::build_index(&env, &query.extra_protected));
            safety::is_protected(&query.path, index, &env.cwd)
        })
        .collect();
    let verdicts = serde_json::to_string(&verdicts).unwrap_or_else(|err| fail(format!("cannot report: {err}")));
    println!("{verdicts}");
}

#[derive(Deserialize)]
struct ScanRequest {
    #[serde(flatten)]
    env: EnvSpec,
    #[serde(default)]
    threads: usize,
    #[serde(default)]
    extra_protected: Vec<String>,
    #[serde(default)]
    never_descend: Vec<String>,
    now: f64,
    walks: Vec<WalkSpec>,
}

fn depth(path: &str) -> usize {
    path.split('/').filter(|c| !c.is_empty()).count()
}

/// What `scanner.run_scan` returns: walk, then — natively — the authoritative
/// protection re-check, the rule thresholds and overlap coalescing.
/// What a scan found, after everything `scanner.run_scan` does to it.
pub struct Scanned {
    pub candidates: Vec<Hit>,
    /// (walk, directory, errno), by walk and then by path.
    pub read_errors: Vec<(usize, String, i32)>,
    pub overlaps_dropped: usize,
    pub dirs: u64,
}

/// The whole scan: the walk, then the containment and protection re-check,
/// the rule thresholds and overlap coalescing.
pub fn native_scan(
    env: &safety::Environment,
    extra_protected: &[String],
    never_descend: &[String],
    threads: usize,
    now: f64,
    specs: &[WalkSpec],
) -> Scanned {
    let index = safety::build_index(env, extra_protected);
    let walks = compile_walks(specs);
    start_pool(threads);
    let ctx = Ctx {
        deny: index.clone(),
        never_descend: never_descend.to_vec(),
        out: Mutex::new(BufWriter::new(io::stdout())),
        dirs: AtomicU64::new(0),
        gather: Some(Mutex::new(Gathered::default())),
    };
    run_walks(&ctx, &walks);
    let Gathered { mut hits, mut read_errors } =
        ctx.gather.as_ref().map(|g| std::mem::take(&mut *g.lock().unwrap_or_else(|e| e.into_inner()))).unwrap_or_default();
    hits.sort_by(|a, b| (a.walk, &a.path).cmp(&(b.walk, &b.path)));
    read_errors.sort();

    // A match becomes a candidate only if it is inside its walk's root, is
    // not protected once fully resolved, and clears its rule's thresholds.
    let mut candidates: Vec<Hit> = Vec::new();
    for hit in hits {
        let spec = &specs[hit.walk];
        let inside = format!("{}/", spec.base.trim_end_matches('/'));
        if !hit.path.starts_with(&inside) || safety::is_protected(&hit.path, &index, &env.cwd) {
            continue;
        }
        let age_days = (now - hit.mtime) / 86400.0;
        if age_days < spec.min_age_days || hit.size < spec.min_size_bytes {
            continue;
        }
        candidates.push(hit);
    }

    // scanner.coalesce: drop what is nested inside another candidate, and
    // exact repeats. Shallower wins; at equal depth, the earlier match.
    let mut order: Vec<usize> = (0..candidates.len()).collect();
    order.sort_by_key(|&i| (depth(&candidates[i].path), i));
    let mut keep = vec![false; candidates.len()];
    let mut kept_paths: HashSet<&str> = HashSet::new();
    let mut overlaps_dropped = 0usize;
    for &i in &order {
        let path = candidates[i].path.as_str();
        let nested = path.match_indices('/').any(|(at, _)| at > 0 && kept_paths.contains(&path[..at]));
        if nested || kept_paths.contains(path) {
            overlaps_dropped += 1;
            continue;
        }
        kept_paths.insert(path);
        keep[i] = true;
    }
    let mut slots: Vec<Option<Hit>> = candidates.into_iter().map(Some).collect();
    let kept = order.into_iter().filter(|&i| keep[i]).filter_map(|i| slots[i].take()).collect();
    Scanned { candidates: kept, read_errors, overlaps_dropped, dirs: ctx.dirs.load(Ordering::Relaxed) }
}

fn scan_main(input: &str) {
    let request: ScanRequest =
        serde_json::from_str(input).unwrap_or_else(|err| fail(format!("bad scan request: {err}")));
    let env = request.env.environment();
    let scanned =
        native_scan(&env, &request.extra_protected, &request.never_descend, request.threads, request.now, &request.walks);
    let result = json!({
        "candidates": scanned.candidates.iter().map(|h| json!({
            "path": h.path, "is_dir": h.is_dir, "size": h.size, "mtime": h.mtime,
            "rule_id": request.walks[h.walk].rule_id,
        })).collect::<Vec<_>>(),
        "errors": scanned.read_errors.iter().map(|(walk, path, errno)| json!({
            "rule_id": request.walks[*walk].rule_id, "path": path, "errno": errno,
        })).collect::<Vec<_>>(),
        "overlaps_dropped": scanned.overlaps_dropped,
        "dirs": scanned.dirs,
    });
    println!("{result}");
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
    fn a_call_that_hangs_is_interrupted() {
        let mut ends = [0 as libc::c_int; 2];
        assert_eq!(unsafe { libc::pipe(ends.as_mut_ptr()) }, 0);
        let started = std::time::Instant::now();

        let watched = unstick::watch();
        let mut byte = 0u8;
        // Nothing is ever written: left alone, this read never returns.
        let read = unsafe { libc::read(ends[0], (&mut byte as *mut u8).cast(), 1) };
        let error = io::Error::last_os_error();
        drop(watched);

        assert_eq!(read, -1);
        assert_eq!(error.kind(), io::ErrorKind::Interrupted);
        assert!(started.elapsed() < std::time::Duration::from_secs(2), "took {:?}", started.elapsed());
        unsafe {
            libc::close(ends[0]);
            libc::close(ends[1]);
        }
    }

    #[test]
    fn interrupted_calls_are_retried_and_other_failures_are_not() {
        let mut calls = 0;
        let outcome = patiently("/anywhere", || {
            calls += 1;
            if calls < 4 { Err(io::Error::from(io::ErrorKind::Interrupted)) } else { Ok(calls) }
        });
        assert_eq!(outcome.ok(), Some(4));

        let mut calls = 0;
        let outcome: io::Result<()> = patiently("/anywhere", || {
            calls += 1;
            Err(io::Error::from(io::ErrorKind::PermissionDenied))
        });
        assert_eq!((outcome.map_err(|e| e.kind()), calls), (Err(io::ErrorKind::PermissionDenied), 1));

        let mut calls = 0;
        let outcome: io::Result<()> = patiently("/anywhere", || {
            calls += 1;
            Err(io::Error::from(io::ErrorKind::Interrupted))
        });
        assert_eq!((outcome.map_err(|e| e.kind()), calls), (Err(io::ErrorKind::Interrupted), LISTING_RETRIES + 1));
    }

    #[test]
    fn only_other_apps_sandboxes_are_watched() {
        assert!(in_containers("/Users/x/Library/Containers/com.apple.Maps/Data"));
        assert!(in_containers("/Users/x/Library/Group Containers/group.example"));
        assert!(!in_containers("/Users/x/Library/Application Support/Code"));
        assert!(!in_containers("/Volumes/Backup/photos"));
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
