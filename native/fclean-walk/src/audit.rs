//! `audit.read_audit_log` and what `fclean audit --json` prints. Reading
//! only: nothing is appended here, and — unlike Python, whose reader creates
//! the log and sets its mode on the way in — nothing is created either. A
//! log that is not there reads as an empty one, which is what Python prints.

use serde::Deserialize;

use crate::fail;
use crate::pyjson::{dumps, J};
use crate::report::{locate, Setup};

#[derive(Deserialize)]
struct Request {
    #[serde(flatten)]
    setup: Setup,
    /// `fclean audit --limit N --action NAME`.
    #[serde(default = "default_limit")]
    limit: i64,
    action: Option<String>,
}

fn default_limit() -> i64 {
    50
}

/// Where `str.splitlines` ends a line: more places than `\n`.
fn ends_line(c: char) -> bool {
    matches!(c, '\n' | '\r' | '\x0b' | '\x0c' | '\x1c' | '\x1d' | '\x1e' | '\u{85}' | '\u{2028}' | '\u{2029}')
}

/// What `str.strip` strips: Unicode white space, and four separators that
/// Python counts as white space and Unicode does not.
fn strips(c: char) -> bool {
    c.is_whitespace() || ('\x1c'..='\x1f').contains(&c)
}

/// Every entry, oldest first; of those, the last `limit` (all of them when
/// it is 0). A line that is not a JSON object is skipped, never fatal.
pub fn read_audit_log(text: &str, limit: usize, action: Option<&str>) -> Vec<serde_json::Value> {
    let action = action.filter(|action| !action.is_empty());
    let mut entries: Vec<serde_json::Value> = text
        .split(ends_line)
        .map(|line| line.trim_matches(strips))
        .filter(|line| !line.is_empty())
        .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
        .filter(|entry| entry.is_object())
        .filter(|entry| action.is_none_or(|action| entry.get("action").and_then(|name| name.as_str()) == Some(action)))
        .collect();
    if limit > 0 && entries.len() > limit {
        entries.drain(..entries.len() - limit);
    }
    entries
}

pub fn main(input: &str) {
    let request: Request =
        serde_json::from_str(input).unwrap_or_else(|err| fail(format!("bad audit-json request: {err}")));
    // Python slices with it: a negative `--limit` drops that many entries
    // from the *start* of the log instead. Refused by name.
    let limit = usize::try_from(request.limit).unwrap_or_else(|_| fail("--limit must not be negative".to_owned()));
    let (_, paths) = locate(&request.setup);
    let log = format!("{}/audit.log", paths.data_dir);
    let text = match std::fs::read(&log) {
        Ok(bytes) => String::from_utf8(bytes).unwrap_or_else(|_| fail(format!("{log} is not valid UTF-8"))),
        Err(_) => String::new(),
    };
    let entries = read_audit_log(&text, limit, request.action.as_deref());
    println!("{}", dumps(&J::dict([("entries", J::List(entries.iter().map(J::from_json).collect()))])));
}

#[cfg(test)]
mod tests {
    use super::*;

    const LOG: &str = "{\"action\": \"scan\", \"n\": 1}\n\nnot json\n[1, 2]\n  {\"action\": \"purge\", \"n\": 2}  \r\n\
                       {\"action\": \"scan\", \"n\": 3}\u{2028}{\"action\": \"scan\", \"n\": 4}\n{\"action\": \"scan\", \"n\": 5";

    fn numbers(entries: &[serde_json::Value]) -> Vec<i64> {
        entries.iter().filter_map(|entry| entry["n"].as_i64()).collect()
    }

    #[test]
    fn malformed_lines_are_skipped_and_the_last_ones_kept() {
        assert_eq!(numbers(&read_audit_log(LOG, 0, None)), [1, 2, 3, 4]);
        assert_eq!(numbers(&read_audit_log(LOG, 2, None)), [3, 4]);
        assert_eq!(numbers(&read_audit_log(LOG, 50, Some(""))), [1, 2, 3, 4]);
    }

    #[test]
    fn the_filter_comes_before_the_limit() {
        assert_eq!(numbers(&read_audit_log(LOG, 2, Some("scan"))), [3, 4]);
        assert_eq!(numbers(&read_audit_log(LOG, 1, Some("purge"))), [2]);
        assert!(read_audit_log(LOG, 0, Some("restore")).is_empty());
    }
}
