# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
