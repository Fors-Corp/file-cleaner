//! `filecleaner.volumes`, as far as a scan needs it: which roots to scan.

use std::collections::HashSet;
use std::ffi::CString;
use std::fs;
use std::os::unix::fs::MetadataExt;

use crate::pypath::{expanduser, normalise};

fn has_usage(path: &str) -> bool {
    let Ok(path) = CString::new(path) else { return false };
    let mut usage: libc::statvfs = unsafe { std::mem::zeroed() };
    unsafe { libc::statvfs(path.as_ptr(), &mut usage) == 0 }
}

/// The non-root half of `list_volumes()`: what is mounted under
/// `volumes_dir`, by name, once per device. The boot volume shows up there
/// too, as an alias of `/`, and is left out the same way.
pub fn external_volumes(volumes_dir: &str) -> Vec<String> {
    let mut seen: HashSet<u64> = fs::metadata("/").map(|root| root.dev()).into_iter().collect();
    let Ok(entries) = fs::read_dir(volumes_dir) else { return Vec::new() };
    let mut names: Vec<String> = entries.flatten().filter_map(|entry| entry.file_name().into_string().ok()).collect();
    names.sort_unstable();
    let mut volumes = Vec::new();
    for name in names {
        let path = format!("{}/{name}", volumes_dir.trim_end_matches('/'));
        let Ok(meta) = fs::metadata(&path) else { continue }; // stat: follows a symlinked mount
        if seen.insert(meta.dev()) && has_usage(&path) {
            volumes.push(path);
        }
    }
    volumes
}

/// `default_scan_roots`: what the config says, or home plus every volume.
pub fn default_scan_roots(configured: &[String], home: &str, volumes_dir: &str) -> Result<Vec<String>, String> {
    if !configured.is_empty() {
        return configured.iter().map(|root| expanduser(root, home)).collect();
    }
    let mut roots = vec![normalise(home)];
    roots.extend(external_volumes(volumes_dir));
    Ok(roots)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn configured_roots_win_and_are_expanded() {
        let configured = ["~/Documents/".to_owned(), "/Volumes/Work".to_owned()];
        let roots = default_scan_roots(&configured, "/Users/x", "/nonexistent").expect("roots");
        assert_eq!(roots, ["/Users/x/Documents", "/Volumes/Work"]);
    }

    #[test]
    fn a_folder_on_the_boot_volume_is_not_an_external_volume() {
        let dir = std::env::temp_dir().join(format!("fclean-walk-volumes-{}", std::process::id()));
        fs::create_dir_all(dir.join("JustAFolder")).expect("scratch dir");
        let temp_is_on_root = fs::metadata(&dir).map(|m| m.dev()).ok() == fs::metadata("/").map(|m| m.dev()).ok();
        let volumes = external_volumes(dir.to_str().expect("utf-8"));
        // Same device as "/": an alias of the boot volume, never a volume of its own.
        assert_eq!(volumes.is_empty(), temp_is_on_root);
        assert_eq!(default_scan_roots(&[], "/Users/x/", "/nonexistent").expect("roots"), ["/Users/x"]);
        let _ = fs::remove_dir_all(&dir);
    }
}
