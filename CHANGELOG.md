# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.4.0] - 2026-09-19

### Changed
- The TUI's scan screen no longer walks the whole tree twice. It used to
  run a counting pre-pass first ("Estimating scan size…") purely so the
  status line could show a percentage, which doubled the time to first
  result. Scan progress now reports a running count of folders scanned
  (`12,500 folders · Logs: scanning …`) straight from the live scan. The
  CLI's progress line, which never had a percentage, gains the same count.
- `scanner.count_total_dirs` and `run_scan(total_dirs=…)` are unchanged
  and still produce a true percentage for any caller that wants to pay
  for the second walk; nothing in File Cleaner does so by default now.

## [1.3.2] - 2026-09-19

### Performance
- Scanning is dramatically faster. Nearly all of a scan's CPU time was
  going into the deny-list check, which runs for every directory entry:
  it rebuilt ~30 `pathlib` objects per ancestor via `in path.parents` and
  re-resolved the home directory, File Cleaner's own install path, every
  mounted volume and every configured `protected_paths` entry on each
  call (~570–950 µs per entry, against ~3 µs for the `lstat`).
  Every deny rule is now flattened once into a tuple of canonical prefixes
  and cached, so a check is a single `str.startswith` (~0.45 µs). Measured
  on the same machine with the same harness: `~/Library/Application
  Support` (505k entries visited) went from 347 s wall / 375 CPU-s to
  1.7 s wall / 2.4 CPU-s, with identical candidates. The home directory
  (3.9M entries), which had been taking 58 minutes, now takes about 80
  seconds — most of which is the kernel's own directory I/O.
- The walk resolves symlinks once, at its start directory, instead of
  once per entry. Symlinked entries were already skipped, so everything
  below a resolved start is resolved by construction and can be checked
  without touching the filesystem. Paths are still reported exactly as
  the root was spelled.

The cached index keeps the existing 5-second refresh, so a volume mounted
mid-scan is still noticed. The check in front of every quarantine move,
restore and purge is unchanged in strength: it still resolves the path
itself, every time.

## [1.3.1] - 2026-09-19

### Security
- The deny-list no longer depends on how a path is spelled. macOS volumes
  are case-insensitive and Unicode-normalisation-insensitive by default,
  and `Path.resolve()` only rewrites a component when it is a symlink — so
  `~/library/mail`, `~/.SSH/id_rsa`, `/system/Library`, or a home directory
  spelled in NFD all opened the real protected directories while comparing
  unequal to the deny-list, and were treated as ordinary, movable paths.
  Both the scan-time filter and the pre-move/restore/purge gate shared the
  check, so neither caught it. Such a spelling could come from a custom
  rule's glob prefix (joined as typed), a hand-edited `plan.json`, or a
  root passed to `duplicates`/`leftovers`. Every deny comparison — absolute
  paths, per-volume and per-home subpaths, File Cleaner's own code, and
  `protected_paths` from config — now uses Unicode canonical caseless
  matching on both sides.
- A path that cannot be resolved at all is now treated as protected rather
  than compared unresolved: if it cannot be shown to be safe, it is not
  touched.

The check is strictly stricter than before, never looser: folding is
applied even on a case-sensitive volume, where it can only protect more.
The scanned-roots allow-list is deliberately left case-sensitive, since
folding an allow-list would loosen it.

### Added
- `tests/safety_cases.json`: a language-neutral conformance table for the
  deny-list (370 path/expected pairs plus the fixture tree they need) —
  case variants of and a symlink into every deny entry, NFC/NFD forms,
  `..` segments, non-existent tails, the `/etc`–`/private/etc` family,
  `/tmp`, mounted volumes, dangling and chained symlinks — so a port to
  another language can run the identical cases. A completeness test fails
  if a deny entry is added without its rows.

## [1.3.0] - 2026-09-13

Smart folder reorganization and real permanent deletion for duplicates and
installation leftovers.

### Added
- `fclean organize <path> [--apply] [--by type|date|date-only]`: proposes
  (and, with `--apply`, performs) sorting loose top-level files into
  type/date/project subfolders. Existing subfolders are never touched or
  descended into. Every applied run is undoable
  (`fclean organize-undo <session>`, sessions listed via
  `fclean organize-sessions`).
- A local, online-learning file classifier (`classify.py`): a hand-rolled,
  zero-dependency multinomial Naive Bayes over hashed filename/extension
  tokens, seeded with an extension→category prior so it's useful
  immediately and improves per-user as the TUI's Organize tab (see below)
  learns from corrections. Never leaves the machine.
- Project/related-file clustering: files sharing a cleaned-up base name
  (`report.docx` + `report_v2.docx` + `report copy.docx`) land together in
  `Projects/<name>/` instead of scattered by type — conservative enough to
  never merge unrelated sequentially-numbered files (camera exports like
  `IMG_1234.jpg`/`IMG_1235.jpg` stay separate).
- macOS screenshot recognition (`Screenshot 2026-09-13 at ....png`) as its
  own Organize category.
- `fclean duplicates <path> --apply [--keep oldest|newest|shortest-path]`:
  **real, permanent deletion** — keeps one copy per duplicate group,
  quarantines the rest, then immediately purges them. Still fully audited,
  hash-verified, and deny-list-checked; only the 30-day wait is skipped.
- `fclean leftovers [--kind apps|installers|all] [--apply]`: two opt-in,
  heuristic detectors — orphaned `~/Library` app-support folders whose
  owning app is no longer in `/Applications`, and installer archives
  (`.dmg`/`.pkg`/`.zip`) in Downloads whose product is already installed
  or extracted. Applying uses the normal quarantine flow (restorable, not
  immediately purged), since these are heuristic guesses and deserve the
  full safety net.
- TUI **Organize** tab: review proposed moves, select and apply them
  (`m`), or re-categorize the highlighted item (`c`) — which both teaches
  the local classifier and sticks for the rest of the session.

## [1.2.0] - 2026-09-13

### Added
- `scan`, `clean`, and `tui` now take an optional directory argument
  (`fclean scan ~/Downloads`) to scope a run to one folder and its
  subfolders, instead of always the whole machine.

### Changed
- **Default scan root changed from the home directory to the current
  working directory.** Running `fclean scan`/`clean`/`tui` with no
  argument now scans only the directory you're in — pass your home
  directory explicitly (e.g. `fclean scan ~`) to get the previous
  whole-machine behavior (home directory + every external volume).
  Rules anchored to a specific path under home (browser caches, dev tool
  caches, etc.) only ever match there, so scoping to an arbitrary folder
  mainly surfaces `.DS_Store` files and your own custom rules. Scripts
  that relied on the old no-argument-means-home-and-volumes default
  should add `~` explicitly.

## [1.1.0] - 2026-09-13

Richer TUI (Rules/Profiles/Stats tabs), per-rule threshold overrides, scan
profiles, macOS launchd scheduling, a live scan percentage, and concurrent
scanning/hashing for faster runs on real disks.

### Added
- The TUI (`fclean tui`) is now a tabbed app: **Scan** (unchanged), **Rules**
  (browse every rule, toggle enabled/disabled, edit per-rule thresholds),
  **Profiles** (apply/save/delete saved scan profiles), and **Stats**
  (current quarantine totals, all-time breakdown by category, recent audit
  activity) — alongside the existing pushed Quarantine screen.
- `rule_param_overrides` config key and `fclean config threshold`/
  `clear-threshold`: override a builtin rule's `min_age_days`/
  `min_size_bytes` without redefining it as a whole custom rule.
- Scan profiles (`fclean profile list/save/apply/show/delete`, new
  `profiles.py`): named, saved snapshots of scan roots, rule
  overrides/thresholds, retention, and hash limits, switchable without
  hand-editing `config.toml`.
- `fclean schedule enable/disable/status` (new `schedule.py`): a macOS
  LaunchAgent that runs a read-only `scan` on a recurring interval, logged
  to the same audit trail the Stats tab reads. Deliberately scoped to
  `scan` only — never `clean --apply`/`purge`.
- `fclean quarantine history`: all-time totals by category and by day
  across everything ever quarantined (including restored/purged items),
  not just what's currently sitting in quarantine.
- A live, real percentage during `scan`/`tui` (a quick pre-pass counts
  directories, then progress is reported against that count) instead of
  just a moving status message.

### Changed
- `run_scan` now walks each rule's targets concurrently in a bounded thread
  pool (new `scan_concurrency` config key, default 4) instead of
  sequentially. Scanning is I/O-bound, and a couple of rules (like the
  `.DS_Store` cleanup rule) walk an entire scan root recursively while most
  others check one small directory — running them concurrently means the
  cheap rules no longer sit blocked behind the expensive ones.
  `duplicates`/`large-files` hashing is parallelized the same way.

### Fixed
- `safety._volume_roots()`'s cached mount-point lookup was read/written
  without a lock; harmless when scanning was sequential, but now that
  rule/root walks run concurrently it's guarded against a race.

## [1.0.0] - 2026-09-08

First production release. Rebuilds the scanning, quarantine, and
configuration layers on top of the original 0.1.0 prototype for
correctness, safety, and testability, and adds a scriptable JSON interface
alongside the human-readable CLI and TUI.

### Added
- `--json` output on every command, so the same engine that powers the CLI
  can sit behind a script or a native GUI without scraping text.
- `fclean clean --save-plan` / `fclean apply`: review an exact candidate
  list, then apply precisely that list later. Every item is re-validated
  against the filesystem at apply time (existence, kind, size, and — for
  directories — recomputed contents) so nothing stale is ever acted on.
- Custom rules via `[[rules]]` tables in `config.toml`, validated the same
  way builtin rules are (safe glob shape, valid risk level, no id clashes).
- `fclean quarantine sessions` and `fclean audit` for reviewing what
  happened and when.
- Per-volume quarantine (`volume_local_quarantine`): an item from an
  external drive is quarantined into a hidden folder on that same drive by
  default — still an instant, same-device move — instead of always
  copying across to the primary quarantine directory.
- `fclean large-files` now uses a bounded min-heap, so memory stays flat
  regardless of how many files a root contains.
- Every filesystem-mutating operation (`quarantine`, `restore`, `purge`)
  returns a structured result listing exactly what happened and, for
  anything skipped, why — visible in both table and `--json` output.

### Changed
- The scanner was rewritten around a proper glob-to-regex engine with
  directory pruning: excluded and protected directories are never entered,
  and a directory matched as a whole is never redundantly descended into.
  A directory's age is now the newest modification time found anywhere
  inside it, not the directory's own mtime — an actively-used cache with
  fresh files inside is no longer misclassified as stale.
- Overlapping matches (the same path reported by two rules, or a path
  nested inside another candidate) are coalesced before anything is shown
  or acted on, so sizes are never double-counted.
- The TUI (`fclean tui`) runs scans on a background worker so the
  interface stays responsive, and every label is rendered as literal text
  rather than parsed as markup — a folder or category name containing
  literal brackets, e.g. `App [Beta]`, now displays correctly rather than
  being silently swallowed by the markup parser.
- Configuration is validated on load and save (type-checked per key, with
  clear errors for a malformed `config.toml`) and written atomically.

### Fixed
- A cross-platform bug where `quarantine purge`'s own safety check
  incorrectly treated the quarantine directory as a protected path,
  making it impossible to ever purge anything.
- The primary TUI keybinding for quarantining a selection never fired
  while the candidate list had focus, because the list widget's own base
  class already binds Enter to an internal action that took priority.
- Version metadata (`fclean --version`) and the config module no longer
  capture path defaults at import time — a class of bug that could ignore
  a relocated home directory or data directory at runtime.

## [0.1.0] - 2026-08-18

Initial prototype: quarantine-based disk cleanup CLI and TUI, exclude
lists, secure purge, and iPhone/iPad backup management.
