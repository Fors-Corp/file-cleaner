//! `plan`: the file `fclean clean --save-plan` writes and `fclean apply`
//! reads back. Saved, loaded and revalidated here; *applying* one moves
//! files, and is not ported.
//!
//! The file is the rollback path between the two implementations, so either
//! must accept what the other writes. This one is the stricter reader: it
//! takes what Python writes, and refuses hand-edited values that Python
//! would coerce (`"12"` for a size, `1` for a flag, `true` for the version).

use std::fs;
use std::io::ErrorKind;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::time::SystemTime;

use serde::Deserialize;
use serde_json::{Map, Value};

use crate::pyjson::{dumps, dumps_ascii, J};
use crate::pypath::{expanduser, normalise};
use crate::report::{candidate_json, locate, scan, strerror, NativeRequest, Scan, Setup};
use crate::rules::repr;
use crate::{dir_stats, fail, mtime_nanos, pytime, st_mtime, start_pool};

const FORMAT_VERSION: i64 = 1;
/// How far a file's time may be from the plan's and still be the same file.
const MTIME_TOLERANCE: f64 = 1e-6;

pub struct Planned {
    pub path: String,
    pub size: i64,
    pub is_dir: bool,
    pub mtime: f64,
    pub rule_id: String,
    pub category: String,
    pub risk: String,
}

impl Planned {
    /// `Candidate.to_dict`.
    fn to_json(&self) -> J {
        J::dict([
            ("path", J::str(&self.path)),
            ("size_bytes", J::Int(self.size)),
            ("is_dir", J::Bool(self.is_dir)),
            ("mtime", J::Float(self.mtime)),
            ("rule_id", J::str(&self.rule_id)),
            ("category", J::str(&self.category)),
            ("risk", J::str(&self.risk)),
        ])
    }
}

fn malformed(what: impl std::fmt::Display) -> String {
    format!("malformed plan file: {what}")
}

/// `Candidate.from_dict`. A missing key is reported in Python's words — a
/// `KeyError` prints as the key's `repr`.
fn planned(item: &Value) -> Result<Planned, String> {
    let item = item.as_object().ok_or_else(|| malformed("a candidate is not an object"))?;
    let field = |key: &str| item.get(key).ok_or_else(|| malformed(repr(key)));
    let text = |key: &str| field(key)?.as_str().map(str::to_owned).ok_or_else(|| malformed(format!("{key} is not text")));
    Ok(Planned {
        path: normalise(&text("path")?),
        size: field("size_bytes")?.as_i64().ok_or_else(|| malformed("size_bytes is not a whole number"))?,
        is_dir: field("is_dir")?.as_bool().ok_or_else(|| malformed("is_dir is not true or false"))?,
        mtime: field("mtime")?.as_f64().ok_or_else(|| malformed("mtime is not a number"))?,
        rule_id: text("rule_id")?,
        category: text("category")?,
        risk: if item.contains_key("risk") { text("risk")? } else { "low".to_owned() },
    })
}

/// `CleanupPlan.from_dict`, as far as `revalidate` needs it.
fn from_dict(data: &Map<String, Value>) -> Result<Vec<Planned>, String> {
    let version = data.get("format_version");
    if version.and_then(Value::as_f64) != Some(FORMAT_VERSION as f64) {
        let shown = match version {
            None | Some(Value::Null) => "None".to_owned(),
            Some(Value::String(text)) => repr(text),
            Some(other) => other.to_string(),
        };
        return Err(format!("unsupported plan format_version {shown} (expected {FORMAT_VERSION})"));
    }
    if data.get("scan_roots").is_some_and(|roots| !roots.is_array()) {
        return Err(malformed("scan_roots is not a list"));
    }
    let candidates = data.get("candidates").ok_or_else(|| malformed(repr("candidates")))?;
    candidates.as_array().ok_or_else(|| malformed("candidates is not a list"))?.iter().map(planned).collect()
}

/// `load_plan`.
pub fn load_plan(path: &str) -> Result<Vec<Planned>, String> {
    let bytes = fs::read(path).map_err(|err| format!("cannot read {path}: {err}"))?;
    let text = String::from_utf8(bytes).map_err(|_| format!("cannot read {path}: it is not UTF-8"))?;
    let data: Value = serde_json::from_str(&text).map_err(|err| format!("{path} is not valid JSON: {err}"))?;
    from_dict(data.as_object().ok_or_else(|| format!("{path}: expected a JSON object"))?)
}

/// `revalidate`: what is still exactly what was reviewed, and what is not,
/// with the reason. A folder's size and time describe everything inside it,
/// so they are taken again the way the scan took them.
pub fn revalidate(plan: Vec<Planned>) -> (Vec<Planned>, Vec<(String, &'static str, Option<String>)>) {
    let mut fresh = Vec::new();
    let mut stale = Vec::new();
    for candidate in plan {
        let meta = match fs::symlink_metadata(&candidate.path) {
            Ok(meta) => meta,
            Err(err) if err.kind() == ErrorKind::NotFound => {
                stale.push((candidate.path, "no longer exists", None));
                continue;
            }
            Err(err) => {
                let why = err.raw_os_error().map_or_else(|| err.to_string(), strerror);
                stale.push((candidate.path, "cannot stat: ", Some(why)));
                continue;
            }
        };
        let own = mtime_nanos(&meta);
        let reason = if meta.file_type().is_symlink() {
            Some("is now a symlink")
        } else if meta.is_dir() != candidate.is_dir {
            Some("changed between file and directory")
        } else if meta.is_dir() {
            let (size, newest) = dir_stats(&candidate.path, own);
            let changed = i64::try_from(size) != Ok(candidate.size) || st_mtime(newest.max(own)) > candidate.mtime + MTIME_TOLERANCE;
            changed.then_some("modified since the plan was written")
        } else {
            let changed = i64::try_from(meta.len()) != Ok(candidate.size) || (st_mtime(own) - candidate.mtime).abs() > MTIME_TOLERANCE;
            changed.then_some("modified since the plan was written")
        };
        match reason {
            Some(reason) => stale.push((candidate.path, reason, None)),
            None => fresh.push(candidate),
        }
    }
    (fresh, stale)
}

#[derive(Deserialize)]
struct CheckRequest {
    #[serde(flatten)]
    setup: Setup,
    plan: String,
}

/// `{"fresh": [...], "stale": [...]}`: what `fclean apply PLAN` would move,
/// and what it would leave and why — without moving anything.
pub fn check_main(input: &str) {
    let request: CheckRequest =
        serde_json::from_str(input).unwrap_or_else(|err| fail(format!("bad plan-check-json request: {err}")));
    let (env, _) = locate(&request.setup);
    let path = expanduser(&request.plan, &env.home).unwrap_or_else(|err| fail(err));
    let plan = load_plan(&path).unwrap_or_else(|err| fail(err));
    start_pool(request.setup.threads);

    let (fresh, stale) = revalidate(plan);
    let skipped = |(path, reason, detail): &(String, &str, Option<String>)| {
        J::dict([("path", J::str(path)), ("reason", J::str(format!("{reason}{}", detail.as_deref().unwrap_or(""))))])
    };
    let report = J::dict([
        ("fresh", J::List(fresh.iter().map(Planned::to_json).collect())),
        ("stale", J::List(stale.iter().map(skipped).collect())),
    ]);
    println!("{}", dumps(&report));
}

#[derive(Deserialize)]
struct SaveRequest {
    #[serde(flatten)]
    scan: NativeRequest,
    /// `fclean clean --save-plan PATH`.
    save_plan: String,
    #[serde(default)]
    note: String,
    /// The clock, when two plans have to be compared.
    created_at: Option<String>,
}

/// `CleanupPlan.from_scan(...).to_dict()`.
fn plan_json(found: &Scan, note: &str, created_at: &str) -> J {
    J::dict([
        ("format_version", J::Int(FORMAT_VERSION)),
        ("tool_version", J::str(env!("CARGO_PKG_VERSION"))),
        ("created_at", J::str(created_at)),
        ("note", J::str(note)),
        ("scan_roots", J::strings(&found.roots)),
        ("total_size_bytes", J::UInt(found.scanned.candidates.iter().map(|hit| hit.size).sum())),
        ("candidate_count", J::UInt(found.scanned.candidates.len() as u64)),
        ("candidates", J::List(found.scanned.candidates.iter().map(|hit| candidate_json(hit, &found.owners[hit.walk])).collect())),
    ])
}

/// `save_plan`: written beside itself and moved into place, readable by its
/// owner alone — it lists what is on the disk.
fn save_plan(plan: &J, path: &str) -> std::io::Result<()> {
    if let Some(parent) = Path::new(path).parent().filter(|parent| !parent.as_os_str().is_empty()) {
        fs::create_dir_all(parent)?;
    }
    let tmp = format!("{path}.tmp");
    fs::write(&tmp, dumps_ascii(plan) + "\n")?;
    let _ = fs::set_permissions(&tmp, fs::Permissions::from_mode(0o600));
    fs::rename(&tmp, path)
}

/// The scan, saved as a plan: `fclean clean --save-plan PATH` without the
/// dry-run table. Writes the one file it is asked to write.
pub fn save_main(input: &str) {
    let request: SaveRequest =
        serde_json::from_str(input).unwrap_or_else(|err| fail(format!("bad plan-save request: {err}")));
    let (env, _) = locate(&request.scan.setup);
    let path = expanduser(&request.save_plan, &env.home).unwrap_or_else(|err| fail(err));
    let created_at = request.created_at.clone().unwrap_or_else(|| {
        // datetime.now(UTC).isoformat(timespec="seconds"): cut, not rounded.
        let seconds = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).map_or(0, |since| since.as_secs() as i64);
        format!("{}+00:00", pytime::isoformat(seconds, 0))
    });

    let found = scan(&request.scan);
    save_plan(&plan_json(&found, &request.note, &created_at), &path).unwrap_or_else(|err| fail(format!("cannot write {path}: {err}")));
    let report = J::dict([("plan", J::str(&path)), ("candidate_count", J::UInt(found.scanned.candidates.len() as u64))]);
    println!("{}", dumps(&report));
}

#[cfg(test)]
mod tests {
    use super::*;

    fn plan(candidate: &str) -> Map<String, Value> {
        let text = format!(r#"{{"format_version": 1, "scan_roots": ["/r"], "candidates": [{candidate}]}}"#);
        serde_json::from_str::<Value>(&text).unwrap().as_object().unwrap().clone()
    }

    const WHOLE: &str = r#"{"path": "/r//a/", "size_bytes": 3, "is_dir": false, "mtime": 5, "rule_id": "x", "category": "C"}"#;

    #[test]
    fn what_python_writes_is_read_back() {
        let read = from_dict(&plan(WHOLE)).unwrap();
        assert_eq!((read[0].path.as_str(), read[0].size, read[0].mtime, read[0].risk.as_str()), ("/r/a", 3, 5.0, "low"));
    }

    #[test]
    fn a_missing_key_is_named_the_way_python_names_it() {
        let without_size = WHOLE.replace(r#""size_bytes": 3, "#, "");
        assert_eq!(from_dict(&plan(&without_size)).err().unwrap(), "malformed plan file: 'size_bytes'");
    }

    #[test]
    fn values_python_would_coerce_are_refused() {
        for (from, to) in [(r#""size_bytes": 3"#, r#""size_bytes": "3""#), (r#""is_dir": false"#, r#""is_dir": 0"#)] {
            assert!(from_dict(&plan(&WHOLE.replace(from, to))).is_err(), "{to}");
        }
        let mut other_version = plan(WHOLE);
        other_version.insert("format_version".to_owned(), Value::from(2));
        assert_eq!(from_dict(&other_version).err().unwrap(), "unsupported plan format_version 2 (expected 1)");
    }
}
