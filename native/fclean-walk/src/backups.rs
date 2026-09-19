//! `backups.find_backups` and what `fclean backups list --json` prints.
//! Listing only: `backups clean` is not ported.
//!
//! Only `Info.plist` and `Manifest.plist` are read — the device's name, the
//! date, whether it is encrypted — never the backed-up data itself.

use std::fs;
use std::io::ErrorKind;

use rayon::prelude::*;
use serde::Deserialize;

use crate::pyjson::{dumps, J};
use crate::pypath::normalise;
use crate::pytime;
use crate::report::{locate, Setup};
use crate::{dir_stats, fail, read_dir, start_pool};

const ACCESS_DENIED: &str = "Can't read the iPhone/iPad backup folder — macOS is blocking access. \
Grant Full Disk Access to your terminal app in System Settings -> \
Privacy & Security -> Full Disk Access, then try again.";

#[derive(Deserialize)]
struct Request {
    #[serde(flatten)]
    setup: Setup,
    /// `find_backups(base)`; the MobileSync folder under home when absent.
    base: Option<String>,
}

pub struct Backup {
    pub udid: String,
    pub path: String,
    pub device_name: String,
    pub product_type: String,
    pub last_backup_date: Option<String>,
    pub size: u64,
    pub encrypted: bool,
}

/// `_load_plist`: a dictionary, or nothing at all.
fn load_plist(path: &str) -> plist::Dictionary {
    plist::Value::from_file(path).ok().and_then(plist::Value::into_dictionary).unwrap_or_default()
}

/// `bool(value)`, for whatever a plist can hold.
fn truthy(value: &plist::Value) -> bool {
    match value {
        plist::Value::Boolean(flag) => *flag,
        plist::Value::Integer(number) => number.as_signed() != Some(0),
        plist::Value::Real(number) => *number != 0.0,
        plist::Value::String(text) => !text.is_empty(),
        plist::Value::Data(bytes) => !bytes.is_empty(),
        plist::Value::Array(items) => !items.is_empty(),
        plist::Value::Dictionary(pairs) => !pairs.is_empty(),
        _ => true, // a date, a UID
    }
}

/// One folder per device backup, in the order the folder lists them. A name
/// or a model that is not text is treated as missing: Python would print
/// whatever it found, and no backup has ever held anything but text there.
pub fn find_backups(base: &str) -> Result<Vec<Backup>, String> {
    if !fs::metadata(base).is_ok_and(|meta| meta.is_dir()) {
        return Ok(Vec::new());
    }
    let entries = read_dir(base).map_err(|err| match err.kind() {
        ErrorKind::PermissionDenied => ACCESS_DENIED.to_owned(),
        _ => format!("cannot read {base}: {err}"),
    })?;
    let folders: Vec<(String, String)> = entries
        .into_iter()
        .filter_map(|entry| entry.file_name().into_string().ok())
        .map(|name| (format!("{base}/{name}"), name))
        .filter(|(path, _)| fs::metadata(path).is_ok_and(|meta| meta.is_dir()))
        .collect();
    // `_dir_size`: every regular file below, symlinks never followed.
    let sizes: Vec<u64> = folders.par_iter().map(|(path, _)| dir_stats(path, 0).0).collect();

    let text = |pairs: &plist::Dictionary, key: &str| pairs.get(key).and_then(plist::Value::as_string).map(str::to_owned);
    Ok(folders
        .into_iter()
        .zip(sizes)
        .map(|((path, udid), size)| {
            let info = load_plist(&format!("{path}/Info.plist"));
            let manifest = load_plist(&format!("{path}/Manifest.plist"));
            Backup {
                device_name: text(&info, "Device Name").filter(|name| !name.is_empty()).unwrap_or_else(|| udid.clone()),
                product_type: text(&info, "Product Type").unwrap_or_default(),
                last_backup_date: info.get("Last Backup Date").and_then(plist::Value::as_date).map(|date| {
                    let (seconds, micros) = pytime::since_epoch(date.into());
                    pytime::isoformat(seconds, micros)
                }),
                encrypted: manifest.get("IsEncrypted").is_some_and(truthy),
                udid,
                path,
                size,
            }
        })
        .collect())
}

pub fn main(input: &str) {
    let request: Request =
        serde_json::from_str(input).unwrap_or_else(|err| fail(format!("bad backups-list-json request: {err}")));
    let (env, _) = locate(&request.setup);
    let base = request.base.as_deref().map(normalise).unwrap_or_else(|| {
        format!("{}/Library/Application Support/MobileSync/Backup", normalise(&env.home))
    });
    start_pool(request.setup.threads);

    let backups = find_backups(&base).unwrap_or_else(|err| fail(err));
    let listed = backups
        .iter()
        .map(|backup| {
            J::dict([
                ("udid", J::str(&backup.udid)),
                ("path", J::str(&backup.path)),
                ("device_name", J::str(&backup.device_name)),
                ("product_type", J::str(&backup.product_type)),
                ("last_backup_date", backup.last_backup_date.as_ref().map_or(J::Null, J::str)),
                ("size_bytes", J::UInt(backup.size)),
                ("encrypted", J::Bool(backup.encrypted)),
            ])
        })
        .collect();
    println!("{}", dumps(&J::dict([("backups", J::List(listed))])));
}
