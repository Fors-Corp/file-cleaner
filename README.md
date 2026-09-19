# File Cleaner

[![CI](https://github.com/marcfs31/file-cleaner/actions/workflows/ci.yml/badge.svg)](https://github.com/marcfs31/file-cleaner/actions/workflows/ci.yml)
![SemVer](https://img.shields.io/badge/versioning-SemVer-blue)
![License](https://img.shields.io/badge/license-All%20Rights%20Reserved-lightgrey)

A local-only disk cleanup tool for macOS (CLI + interactive TUI) built around one rule:
**nothing is ever permanently deleted without an explicit, confirmed step.** Everything
`clean` matches gets moved into a local quarantine folder first — restorable any time —
and stays there for a configurable retention window before it's even *eligible* for a
separate, typed-confirmation `purge`.

No network calls, no telemetry, ever. Everything runs on this machine, on your files.

## Install

```bash
./install.sh
./fclean --help
```

This creates a project-local virtualenv (`.venv`) and installs File Cleaner into it —
no system-wide changes, no sudo. `./fclean` is a small wrapper script that runs the venv's
copy. Optionally put it on your `PATH`:

```bash
export PATH="$(pwd):$PATH"
```

Requires Python 3.11+ and macOS. Also runnable as `python -m filecleaner`.

### Optional: the native scan walker

If a Rust toolchain (`cargo`) is on your `PATH`, `install.sh` also builds `fclean-walk`, a
small native helper that does the directory walk for `scan`, `duplicates` and `large-files`.
It is several times faster on a large tree (a whole-home `scan` of ~336k folders: about 15 s
instead of about 75 s; the file walk behind `duplicates`, 3.2M files: about 28 s instead of
about 230 s) because
it lists directories on every core at once, walks the tree once for rules that start in the
same place, and sizes matched folders with macOS's bulk `getattrlistbulk(2)` call instead
of one `lstat` per file. Results are identical; it only changes how long you wait.

It is strictly optional and strictly an accelerator. Without it File Cleaner behaves the
same and walks in Python; if the helper ever fails, the scan warns and falls back to Python.
The helper is only ever loaded from inside the installed package (or from the path in
`FCLEAN_NATIVE_WALK`), never from `PATH`, and the scanner re-checks every path it reports
against the deny-list before using it. For `duplicates`, what counts as a duplicate is still
decided in Python: it hashes the files itself and checks that they really are different
physical files. Set `FCLEAN_NATIVE_WALK=0` to force the Python walker. After updating File
Cleaner, re-run `./install.sh` so the helper is rebuilt to match.

## Quick start

```bash
fclean doctor          # volumes, config, quarantine health, FileVault status — read-only
fclean scan             # what could be cleaned up in the current directory — read-only
fclean clean             # same, but with --apply it actually moves matches to quarantine
fclean tui                 # interactive browser: select items, see live disk usage, confirm
```

`scan`, `clean`, and `tui` all take an optional directory argument and default to **the
current directory** — `fclean scan` scans wherever you run it from, and `fclean scan ~/Downloads`
(or `cd ~/Downloads && fclean scan`) scopes it to just that folder and its subfolders. Pass
your home directory to get the traditional whole-machine scan across every external volume
too:

```bash
fclean scan ~/Downloads     # just this folder
fclean scan ~                 # whole machine: home directory + every external volume
```

Rules anchored to a specific path under home (like browser caches under `Library/Caches/`)
only ever match there, so scoping to an arbitrary folder mainly surfaces things like stray
`.DS_Store` files and your own custom rules — see [What gets cleaned](#what-gets-cleaned).

`scan` and `clean` (without `--apply`) never modify anything — they're always safe to run.
Every command also accepts `--json` for machine-readable output (see
[Scripting and the JSON interface](#scripting-and-the-json-interface)).

## How the safety net works

1. **Dry-run by default.** `clean` only *reports* what it would do unless you pass `--apply`.
2. **Quarantine, not deletion.** `--apply` moves matches into quarantine, preserving their
   original path structure. On the same volume this is an instant rename — no extra free
   space is needed, which matters if your disk is nearly full. An item from an *external*
   drive is quarantined into a hidden folder on that same drive by default (still an
   instant move, no cross-device copy) rather than always routing through the primary
   quarantine directory — see `volume_local_quarantine` in [Configuration](#configuration).
3. **Full manifest.** Every quarantined item is recorded in a local SQLite database
   (`quarantine/manifest.db`) with its original path, size, timestamp, matched rule, and a
   hash — enough to restore it precisely.
4. **Restore any time** within the retention window:
   ```bash
   fclean restore --session <id>          # everything from one clean run
   fclean restore --path "Downloads"       # anything whose original path matches
   fclean restore --ids 12,13              # specific quarantine entries
   fclean quarantine list                  # see what's in quarantine right now
   fclean quarantine sessions              # one row per clean/apply run, with totals
   ```
5. **Purge is separate, explicit, and confirmed.** Nothing leaves quarantine on its own.
   ```bash
   fclean quarantine purge                 # purges only items past the retention window
   fclean quarantine purge --older-than 7  # custom age threshold
   fclean quarantine purge --session <id>  # only items from one session
   fclean quarantine purge --all           # everything, regardless of age
   ```
   Each of these prints exactly what will be deleted and requires typing `yes` (or `--yes`
   to skip the prompt in scripts — omitting both when there's no real terminal to type into
   is refused outright, never silently assumed). `--secure` additionally overwrites file
   bytes before removal — see [Secure deletion](#secure-deletion-what-actually-works) below
   for why this is extra, not required, on this Mac.
6. **A hardcoded deny-list** (`safety.py`) blocks system paths (`/System`, `/usr`, `/bin`,
   `/Applications`, Keychains, Mail/Messages/Photos data, etc.) from ever being touched, no
   matter what a rule matches or how config is set. It cannot be weakened from config — only
   narrowed further with `fclean config keep <path>`.
7. **Full audit trail** — every scan/clean/restore/purge is appended to a local audit log
   (JSON lines, metadata only, never file contents), browsable with `fclean audit`.

## Reviewing a plan before it runs

`clean --apply` scans and acts in one step. For anything you want to review more
deliberately — a large sweep, an unattended script, or just double-checking before a big
cleanup — save the exact candidate list first, look it over, then apply precisely that list:

```bash
fclean clean --save-plan cleanup.json    # scan and write the plan; nothing is moved
cat cleanup.json                         # or open it, review the paths and sizes
fclean apply cleanup.json --yes          # quarantine exactly those items, nothing else
```

Every item is re-checked against the filesystem at apply time — anything that no longer
exists, changed size, or changed from a file to a directory (or vice versa) since the plan
was written is skipped and reported, never silently substituted or force-applied.

## What gets cleaned

Run `fclean config show` to see every rule, its category, risk level, and whether it's
enabled. Roughly:

| Category | Examples | Default |
|---|---|---|
| Logs | Crash/diagnostic reports, `~/Library/Logs` | on |
| Caches | Browser HTTP caches, `~/Library/Caches/*` | on |
| Trash | `~/.Trash`, external drives' `.Trashes` | on |
| System junk | `.DS_Store` | on |
| Developer | Xcode DerivedData/DeviceSupport/Simulator caches, npm/yarn/pnpm/pip/Homebrew/Gradle/Cargo caches | on |
| Developer (opt-in) | Xcode Archives, Docker Desktop logs, old `node_modules` (30+ days untouched) | **off** |
| Personal (opt-in) | Mail attachment downloads, old files in `~/Downloads` (90+ days) | **off** |

Opt-in categories are real cleanup options but require a judgment call about what's still
needed, so they're excluded from the default sweep. Enable one with:
```bash
fclean config enable dev_node_modules
```

Limit any `scan`/`clean` run to specific rules with `--rules id1,id2`, or see disabled
categories too with `--include-disabled`.

### Custom rules

Add your own rules in `config.toml` as `[[rules]]` tables — validated the same way builtin
rules are (relative globs only, no `..`, a real risk level):

```toml
[[rules]]
id = "old_isos"
label = "Old disk images in Downloads"
category = "Personal (opt-in)"
include = ["Downloads/*.iso", "Downloads/*.dmg"]
min_age_days = 60
risk = "medium"
enabled = false
```

Fields: `id` and `include` are required; `label`, `category`, `description`, `exclude`,
`kind` (`file`/`dir`, default `file`), `scope` (`home`/`each_volume`, default `home`),
`min_age_days`, `min_size_bytes`, `risk` (`low`/`medium`/`high`), and `enabled` are all
optional. A custom `id` cannot reuse a builtin one.

## Keeping specific things

```bash
fclean config keep ~/Projects/important-app/node_modules   # permanent — every future run
fclean config unkeep ~/Projects/important-app/node_modules # remove from the keep list
fclean clean --exclude ~/Downloads/tax-docs                # one-off, this run only
```

## Duplicates and large files

```bash
fclean duplicates ~/Pictures --top 20     # groups of identical files by content hash
fclean large-files ~/ --top 50            # biggest files under a path
```

Read-only by default. `large-files` uses a bounded min-heap internally, so memory use stays
flat no matter how many files a root contains. `duplicates` can also **permanently delete**
the extra copies:

```bash
fclean duplicates ~/Pictures --apply --keep oldest
```

Keeps one copy per group (`--keep oldest`/`newest`/`shortest-path`, default `oldest`) and
quarantines the rest, then *immediately* purges them — still fully audited, hash-verified,
and checked against the deny-list, just without the usual 30-day wait, since two
byte-identical files don't need one. Confirms first unless `--yes` is passed.

## Organizing files

```bash
fclean organize ~/Downloads                          # dry-run: what would move where
fclean organize ~/Downloads --apply                   # actually move it
fclean organize ~/Desktop --apply --by date            # group by year/month instead of type
fclean organize-sessions                                  # list past runs
fclean organize-undo <session-id>                            # put one run's files back
```

Only loose files directly inside the given folder are considered — existing subfolders are
never touched or descended into, so anything you've already organized by hand is left
alone. Files land in a category (Documents, Images, Installers, Code, …) chosen by:
1. **Project clustering** — files sharing a cleaned-up base name (`report.docx` +
   `report_v2.docx` + `report copy.docx`) land together in `Projects/<name>/`, conservative
   enough to never merge unrelated sequentially-numbered files (`IMG_1234.jpg`/
   `IMG_1235.jpg` stay separate — no `.docx`/`.dmg`/etc.-style "version marker" links them).
2. **A confident extension prior** (`.pdf` → Documents, `.dmg`/`.pkg` → Installers, a
   macOS screenshot filename → Screenshots).
3. **A small local classifier** (`classify.py`) for anything else — a hand-rolled,
   zero-dependency statistical model (no ML framework, no network call, nothing leaves the
   machine) seeded with the same extension priors so it's useful immediately, and that
   learns from your corrections in the TUI's **Organize** tab over time. Its guesses come
   with a confidence score; low-confidence ones are flagged `(low confidence, review)`
   rather than silently acted on.

Every `--apply` is recorded as a session (same idea as quarantine sessions, separate
table) so it can be fully undone with `organize-undo`.

## Leftover installation files

```bash
fclean leftovers                       # both detectors, read-only report
fclean leftovers --kind apps           # just orphaned ~/Library folders
fclean leftovers --kind installers     # just already-used installer archives
fclean leftovers --apply               # quarantine the findings (normal safety net)
```

Two opt-in, heuristic detectors that cross-reference *other* filesystem state — something
the glob-based rules can't do:
- **App leftovers**: subfolders under `~/Library/{Application Support,Caches,Preferences,…}`
  whose owning app (matched by bundle id, read from every `/Applications/*.app`'s
  `Info.plist`) is no longer installed.
- **Installer cleanup**: `.dmg`/`.pkg`/`.zip` files in Downloads whose apparent product
  already exists — a matching-name installed app, or an already-extracted sibling folder.

Folder-naming heuristics have real false-positive potential (a Mac App Store sandbox
container, a CLI tool with no `.app` bundle), so results are risk `medium`/`high` — always
review the list before `--apply`. Applying goes through the *normal* quarantine flow
(restorable for the usual retention window, not immediately purged like duplicates), since
these are educated guesses and deserve the full safety net.

## iPhone/iPad backup management

Backups made via Finder/cable land in `~/Library/Application Support/MobileSync/Backup/`
on *this Mac's* disk — often 20-100GB+ each, and they pile up.

```bash
fclean backups list                              # every local backup: device, date, size
fclean backups clean --keep-latest 1 --apply      # quarantine all but the newest per device
```

This folder is privacy-protected by macOS (TCC). If you see a permission error, grant
**Full Disk Access** to your terminal app in System Settings → Privacy & Security → Full
Disk Access, then retry. Stale backups go through the same quarantine pipeline as
everything else — fully restorable.

## Device app management (experimental, unverified)

```bash
fclean device list        # iOS devices connected over USB
fclean device apps        # installed apps + on-device storage usage
fclean device uninstall <bundle-id>
```

iOS doesn't allow general file/cache browsing from a computer — Apple blocks that for
privacy, cable or not. What *is* possible without a jailbreak is app-level management via
`pymobiledevice3` (pip-installable, no Homebrew needed): `pip install "filecleaner[device]"`.

**This was built without a physical iPhone/iPad available to test against.** It needs the
device plugged in, unlocked, and paired — tap "Trust This Computer" on the device itself
when prompted. Try `fclean device list` first; if anything about the app-listing or
uninstall commands misbehaves against a real device, that's expected for a first pass —
check `src/filecleaner/device.py`, which documents the exact pymobiledevice3 calls in use.
Uninstalling an app removes its on-device data too, and — unlike everything else in this
tool — that is **not** restorable by File Cleaner (only by reinstalling the app fresh).

## The interactive TUI

`fclean tui [path]` launches a full-screen browser across five tabs — **Scan**, **Rules**,
**Profiles**, **Stats**, **Organize** — plus a pushed **Quarantine** screen. Everything is
keyboard-driven — the footer always shows the active bindings, and none of it is
mouse-only:

| Key | Action |
|---|---|
| ↑ / ↓ | Move the highlight |
| Space | Toggle the highlighted item (select a candidate; enable/disable a rule) |
| `a` / `n` | Select all / select none (Scan, Rules, and Organize tabs) |
| `x` | Quarantine the selected items (Scan tab; opens a confirm dialog) |
| `e` | Edit the highlighted rule's thresholds (Rules tab) |
| `s` | Save the current config as a new named profile (Profiles tab) |
| `d` | Delete the highlighted profile (Profiles tab) |
| `m` | Move the selected files (Organize tab; opens a confirm dialog) |
| `c` | Re-categorize the highlighted file (Organize tab) |
| `u` | Open the quarantine/restore screen |
| `r` | Rescan (Scan tab) / refresh the plan (Organize tab) / restore selected (Quarantine screen) |
| `q` | Quit |

**Scan** is the original candidate browser: select matches, see live disk usage, and
confirm before anything moves — a running count of folders scanned shows the scan is
live, without walking the tree a second time just to compute a percentage. **Rules** lists every builtin and
custom rule with its category, risk, and effective thresholds; toggling one writes
straight to `rule_overrides`, and `e` opens a small dialog to override a rule's
`min_age_days`/`min_size_bytes` without redefining it as a custom rule (leaving a field
blank clears that override). **Profiles** lists saved profiles (see
[Scan profiles](#scan-profiles) below) — `enter` applies the highlighted one, `s` saves
the current config as a new one. **Stats** shows what's currently in quarantine, an
all-time breakdown by category, and the most recent entries from the audit log — reusing
the manifest and audit trail that already exist rather than a separate history store.
**Organize** (see [Organizing files](#organizing-files)) lists the same root's proposed
moves — select and `m` to apply, or `c` on the highlighted item to override its category,
which both teaches the local classifier and sticks for the rest of the session (a single
correction rarely outweighs the seeded prior enough to immediately flip that one file's
prediction on its own).

The confirm dialog never defaults to "yes": focus starts on **Cancel**, so pressing Enter
without deliberately tabbing to **Confirm** safely cancels. Escape always cancels
immediately. Long scans run in the background so the interface never freezes, and every
label — including a raw filesystem path or a custom rule's category name — is rendered as
literal text rather than parsed as markup, so a folder or category containing a literal
bracket (`App [Beta]`, a category named `Caches`) always displays exactly as it is instead
of being silently mistaken for a formatting tag.

The app follows your terminal's light/dark theme and resizes with the window — there is no
fixed-width layout to clip.

## Scripting and the JSON interface

Every command accepts `--json`, emitting a stable, structured document instead of a table —
the same engine that renders the CLI's tables and the TUI's lists. This makes File Cleaner
usable as a building block: a `launchd` job that emails you when reclaimable space crosses
a threshold, a Shortcuts action, or a future native GUI, all without scraping text output.

```bash
fclean scan --json | jq '.total_size_bytes'
fclean quarantine list --json | jq '.entries[] | select(.category == "Developer")'
```

Errors go to a clean, single-line message on stderr with a non-zero exit code — never a
Python traceback — so scripts can rely on `$?` alone.

## Secure deletion: what actually works

`quarantine purge --secure` overwrites a file's bytes before removing it. Worth knowing
before relying on it: this Mac's disk is SSD/flash storage, and on flash storage,
overwrite-based "secure delete" doesn't give the same guarantee it did on spinning disks —
wear-leveling and the flash translation layer mean the logical block you overwrite often
isn't the same physical NAND cell the original data lived in. This is exactly why Apple
removed "Secure Empty Trash" and secure-erase from Disk Utility years ago.

What *does* give a real, instant guarantee: **FileVault**. If it's on (check with
`fclean doctor`), the disk is encrypted at rest, and the moment `purge` removes a file,
its plaintext becomes cryptographically inaccessible regardless of what remains on the
physical flash chips. `--secure` is belt-and-suspenders on top of that, not a replacement
for it.

For wiping an entire machine clean (not File Cleaner's job — a different, OS-level
operation), macOS's built-in **Erase All Content and Settings**
(System Settings → General → Transfer or Reset) does a proper cryptographic wipe of
everything, correctly handling system state and Keychain in a way no userland script can.

## Privacy

- No network calls anywhere in this tool, no telemetry, nothing phones home.
- File *contents* are never read except to compute a hash for duplicate detection or
  quarantine manifest integrity — streamed in chunks, never logged, never stored.
- Config, quarantine manifest, and audit log live under `~/.config/filecleaner/` and
  `~/.filecleaner/` with restrictive permissions (`0700` dirs, `0600` files), since paths
  and filenames can reveal personal information. Both locations are themselves permanently
  excluded from every scan, quarantine, and purge — File Cleaner never treats its own
  safety net as junk.

## Configuration

`~/.config/filecleaner/config.toml`, created on first run (override the location with the
`FILECLEANER_CONFIG_DIR` / `FILECLEANER_DATA_DIR` environment variables):

```toml
retention_days = 30
quarantine_dir = "/Users/you/.filecleaner/quarantine"   # can point anywhere, e.g. an external drive
volume_local_quarantine = true                           # quarantine external-volume items locally to that volume
protected_paths = []                                     # populated by `config keep`
scan_roots = []                                           # empty = home dir + external volumes
rule_overrides = {}                                        # rule_id -> true/false
rule_param_overrides = {}                                   # rule_id -> {min_age_days = .., min_size_bytes = ..}
scan_concurrency = 4                                          # max (rule, root) walks run in parallel during a scan
hash_duplicates_max_bytes = 2000000000                       # skip hashing files bigger than this
active_profile = ""                                            # set by `fclean profile apply <name>`
# rules = [[ ... ]]                                            # custom rules — see "Custom rules" above
```

Edit directly, or via `fclean config set <key> <value>` / `config enable|disable <rule-id>` /
`config keep|unkeep <path>` / `config threshold <rule-id> [--min-age-days N] [--min-size-bytes N]`
(and `config clear-threshold <rule-id>` to remove an override). An invalid config (bad TOML,
wrong value type, an unknown rule id in `rule_overrides`/`rule_param_overrides`) is reported
clearly rather than silently ignored or crashing.

Scanning is I/O-bound (mostly `os.scandir`/`stat` syscalls), so `run_scan` walks every
selected rule's `(rule, root)` target concurrently in a bounded thread pool — `scan_concurrency`
sets how many run at once. This matters in practice because rules vary hugely in cost: a
couple of rules (like the built-in `.DS_Store` cleanup rule) walk the *entire* scan root
recursively, while most others only look at one small, specific directory — running them
sequentially meant the cheap rules sat idle behind the expensive one. `duplicates`/`large-files`
hashing is parallelized the same way, and reuses the same setting.

## Scan profiles

A profile is a named, saved snapshot of `scan_roots`, `rule_overrides`,
`rule_param_overrides`, `retention_days`, and `hash_duplicates_max_bytes` — everything else
(quarantine location, protected paths, etc.) always comes from the base config regardless of
which profile is active. Useful for switching between, say, a fast "quick" pass and a
thorough "deep" one, or a profile scoped to external drives only.

```bash
fclean profile save quick        # save the current config's tracked keys under this name
fclean profile list                 # list saved profiles, marking the active one
fclean profile apply quick             # layer "quick"'s keys onto the config and make it active
fclean profile show quick                 # print what's stored in a profile
fclean profile delete quick                  # remove it
```

The same actions are available from the TUI's **Profiles** tab (`enter` to apply, `s` to
save, `d` to delete).

## Scheduling scans

`fclean schedule enable` installs a macOS LaunchAgent that runs `fclean scan --json` on a
recurring interval — output goes to a log file under `~/.filecleaner/schedule/`, and each run
feeds the same audit trail (and so the same Stats tab) as a scan you run yourself.

```bash
fclean schedule enable --every-hours 24
fclean schedule status
fclean schedule disable
```

This is deliberately scoped to the read-only `scan` command — it will never schedule
`clean --apply` or `purge`. Those stay an explicit, interactive decision every time, which is
the whole point of this app's confirm-before-anything-moves design; unattended automation
that could quarantine or delete things on its own would defeat that.

## Development

```bash
.venv/bin/pip install -e ".[dev]"
.venv/bin/pytest              # unit, CLI (Typer's CliRunner), and TUI (Textual's Pilot) tests
.venv/bin/ruff check src/ tests/
.venv/bin/mypy src/filecleaner
```

All tests run against synthetic `tmp_path` sandboxes (via `tests/conftest.py`, which
redirects `Path.home()`, `$HOME`, and every config/data/quarantine path) — never the real
filesystem, and never require a real iPhone or real MobileSync backups. CI (GitHub Actions,
`.github/workflows/ci.yml`) runs the same three commands on macOS across Python 3.11–3.13.

The native scan walker lives in `native/fclean-walk` (Rust):

```bash
cargo test --release --manifest-path native/fclean-walk/Cargo.toml
cargo build --release --manifest-path native/fclean-walk/Cargo.toml
```

`tests/test_native_walk.py` runs the built helper against the Python walker — which stays
the reference implementation — and is skipped if it has not been built. To push the rest of
the suite through it too: `FCLEAN_NATIVE_WALK="$PWD/native/fclean-walk/target/release/fclean-walk" .venv/bin/pytest`.
`scanner.glob_to_regex` and the helper's port of it must be kept in step.

## Architecture, and where this could go next

The codebase is layered as a dependency-free **engine** — `models`, `config`, `safety`,
`rules`, `scanner`, `duplicates`, `largefiles`, `quarantine`, `plan`, `audit`, `profiles`,
`schedule` — with two thin front-ends on top of it: the Typer CLI (`cli.py`) and the
Textual TUI (`tui.py`). The engine never imports either front-end, every mutating call
returns a structured result (`ScanResult`, `ActionResult`) rather than printing directly,
and `output.py` turns any of that into the JSON documents `--json` emits. That separation
is what makes `--json` and the plan/apply workflow possible without duplicating logic
between the CLI and the TUI — it's also what let the **Rules**/**Profiles**/**Stats** TUI
tabs and `fclean schedule` reuse the same engine functions the CLI's `config`/`profile`
commands and `scan` already used, rather than growing a second implementation.

The background-agent idea from earlier versions of this doc is now `fclean schedule` —
a `launchd` user agent that runs a read-only `scan` on an interval (see
[Scheduling scans](#scheduling-scans)). What's still a natural next step, building on the
same seam: a lightweight **menu-bar app** (SwiftUI, talking to the existing engine either
by shelling out to `fclean --json` or, for tighter integration, via a small XPC service
wrapping the same Python engine) that posts a native notification when reclaimable space
crosses a threshold and shows live free-space/quarantine-size next to the clock — no
polling from a foreground app needed. Nothing about the current engine/front-end split
needs to change to build that; it is already the seam such an app would plug into.

## Known limitations

- macOS only (Library/Caches conventions, `/Volumes`, `fdesetup`, etc.) — no Windows/Linux support.
- No general iOS file/cache browsing over cable — not possible without a jailbreak; see
  the device management section above for what's actually feasible.
- No native GUI app (SwiftUI) — the Textual TUI is the interactive interface for this pass;
  see [Architecture](#architecture-and-where-this-could-go-next) for a concrete path there.
- The `device` subcommands are unverified against real hardware (see above).

## Versioning

This project follows [Semantic Versioning](https://semver.org/). See
[CHANGELOG.md](CHANGELOG.md) for release history.

## License

All rights reserved — see [LICENSE](LICENSE). This repository is public for visibility
only; no license to use, copy, modify, or distribute the code is granted. Contact
developer@marcfors.com for permissions.
