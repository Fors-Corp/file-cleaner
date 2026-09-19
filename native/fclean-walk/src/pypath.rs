//! The two things pathlib does to a path before File Cleaner ever sees it:
//! `str(Path(text))` and `Path.expanduser()`.

/// `str(PurePosixPath(text))`: repeated slashes and `.` components dropped,
/// no trailing slash, `..` kept. Exactly two leading slashes survive (POSIX
/// leaves their meaning to the implementation); three or more are one.
pub fn normalise(text: &str) -> String {
    let leading = text.len() - text.trim_start_matches('/').len();
    let root = match leading {
        0 => "",
        2 => "//",
        _ => "/",
    };
    let parts: Vec<&str> = text.split('/').filter(|part| !part.is_empty() && *part != ".").collect();
    if parts.is_empty() {
        return if root.is_empty() { ".".to_owned() } else { root.to_owned() };
    }
    format!("{root}{}", parts.join("/"))
}

/// `Path(text).expanduser()`, for `~` and `~/...`. `~name` needs the
/// password database; nothing in a config has ever needed it, so it is
/// refused by name rather than quietly left unexpanded.
pub fn expanduser(text: &str, home: &str) -> Result<String, String> {
    let path = normalise(text);
    if path == "~" {
        return Ok(normalise(home));
    }
    if let Some(rest) = path.strip_prefix("~/") {
        return Ok(normalise(&format!("{home}/{rest}")));
    }
    if path.starts_with('~') {
        return Err(format!("{text}: '~user' paths are not supported by the native port"));
    }
    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalise_is_str_of_path() {
        for (text, expected) in [
            ("/a/b/", "/a/b"),
            ("/a//b/./c", "/a/b/c"),
            ("a/./b", "a/b"),
            ("", "."),
            (".", "."),
            ("/", "/"),
            ("//", "//"),
            ("//a", "//a"),
            ("///a", "/a"),
            ("/a/../b", "/a/../b"),
            ("./a", "a"),
        ] {
            assert_eq!(normalise(text), expected, "{text:?}");
        }
    }

    #[test]
    fn expanduser_knows_home_and_refuses_other_users() {
        assert_eq!(expanduser("~", "/Users/x").as_deref(), Ok("/Users/x"));
        assert_eq!(expanduser("~/Library/", "/Users/x").as_deref(), Ok("/Users/x/Library"));
        assert_eq!(expanduser("/tmp/~", "/Users/x").as_deref(), Ok("/tmp/~"));
        assert_eq!(expanduser("relative/x", "/Users/x").as_deref(), Ok("relative/x"));
        assert!(expanduser("~root/x", "/Users/x").is_err());
    }
}
