# Porting File Cleaner to Rust

Status: **phase 1 in progress.** Decided 2026-09-19. This file is the plan of
record; update it as phases land.

## Why, and why not

The port is **not for speed.** Measured on 2026-09-19: the 58-minute scan was a
Python bug (`safety.is_protected`), fixed in 1.3.2; what remains is kernel
directory I/O, which the Rust helper `fclean-walk` already spreads across every
core (1.5.0, 1.6.0). Past 8 threads APFS lock contention eats any further gain,
in any language.

The reasons that hold are: **one static binary** (no Python, venv or
`install.sh`), and **one language** instead of Python plus a Rust helper.

Rust rather than Go because the walker, the `getattrlistbulk(2)` FFI, the
glob→regex port and the deny-list comparison key already exist, tested, in
`native/fclean-walk`. There is no speed difference between the two here.

## The rule that governs everything

Every safety bug found in this codebase was a small mistake about *spelling* or
*identity* — case-folding (1.3.1), one file under two paths (1.5.2), a path
captured at import (1.5.1). A port is the ideal place to reintroduce all three.
So:

1. **Python is the reference until a phase is proven, not until it is written.**
   A phase is done when its parity check passes on real data, not when it
   compiles.
2. **Nothing that mutates the filesystem is ported until everything read-only
   underneath it is proven identical.** Order is by blast radius, not by
   convenience.
3. **The deny-list may only get stricter.** Any divergence from Python must be
   in the safe direction and written down here.
4. **One source of truth for data.** Deny-lists and builtin rules must not live
   as two hand-maintained copies; until Python is retired, a test asserts the
   two are equal.
5. Mutating phases are developed and tested **only against tmp fixtures and
   copies of the real `manifest.db`**, never the real quarantine.

## Parity oracles

| Oracle | What it proves |
|---|---|
| `tests/safety_cases.json` (370 cases + fixture tree) | The deny-list verdict, per path, in any language. |
| `tools/safety_differential.py` | Never looser than a reference, over ~650k real paths, against an inode-identity oracle. |
| `tools/port_parity.py` | The Rust `scan` reports the same candidates (path, kind, size, rule) as Python's `run_scan` on a real directory. |
| The pytest suite (722 tests) | Behaviour of each command; ported commands must pass the same assertions through a thin adapter. |
| `tools/bench_scan.py` | "Faster" is not "did less": directories listed, entries seen, candidate fingerprint. |

## Phases

Sizes are the Python being replaced. Each phase ships behind the Python CLI
until phase 5 flips the entry point.

### Phase 1 — read-only core: deny-list + scan engine  *(done 2026-09-19)*
`safety` (233) · the walk already in `fclean-walk` · thresholds + coalescing
from `scanner` (674).

- `safety` in Rust in full: non-strict symlink resolution, deny-index
  construction (home, mounted volumes, own install dir, extra paths),
  `is_protected`. Must pass all 370 table cases and the differential.
- `fclean-walk scan`: the existing walk **plus** rule thresholds, the
  authoritative protection re-check and overlap coalescing, natively — i.e.
  what `scanner.run_scan` returns, with no Python in the loop.
- Rules and config still come from Python (exported as JSON per request).
  Production scans are unchanged: Python stays authoritative and keeps
  re-checking the helper. The native `scan` runs only under the parity tool.

*Done when:* table 370/370; differential 0 looser / 0 oracle violations;
`port_parity.py` identical on a fixture tree in CI and on the real home
directory by hand.

*Known intentional divergence:* a symlink loop is unresolvable, so Rust treats
it as protected everywhere. Python ≥ 3.13 resolves a loop to itself and may
call it unprotected outside a deny dir. Stricter, so allowed.

A second one, found in review: a mounted volume whose name is not valid UTF-8
cannot be written as a deny key in Rust, so Rust protects all of `/Volumes`
while one is mounted. Python names it through surrogate escapes. APFS refuses
to create such a name, so this is not reachable on a stock Mac. Stricter.

*Result (2026-09-19, macOS 26, APFS):*

| Check | Outcome |
|---|---|
| Conformance table, Rust (`test_table_holds_for_the_rust_port`) | 370/370 |
| Deny lists identical to Python's (`test_the_rust_port_carries_the_same_deny_lists`) | yes |
| `port_parity.py protected` — 338,555 real paths and respellings | 0 looser, 0 stricter |
| `port_parity.py scan ~` — real home, read-only | 374 = 374 candidates, same kind, size and rule; 8 = 8 errors; Python 88 s, Rust 19 s |
| Fixture-tree parity in CI (`tests/test_port_parity.py`) | thresholds, exact ties, nesting, protected places, unreadable dirs |

The inode-identity oracle was not re-run against Rust: it holds for Python
(0 violations), and Rust agrees with Python on every path, in both directions.

### Phase 2 — data and configuration  *(done 2026-09-19)*
`rules` (412) · `models.Rule`/`Candidate`/`ScanResult` · `config`, reading
half (445) · `volumes`, scan roots (136) · `output` (34).

- The builtin rules are a data file, `src/filecleaner/builtin_rules.json`:
  Python loads it, Rust compiles it in (`include_str!`). One list, two
  readers. Generated from the tuple it replaced; `repr(BUILTIN_RULES)` hashes
  the same before and after, and the file is in the built wheel.
- `fclean-walk scan-json` and `config-json`: config file (same paths and
  environment variables, defaults, validation and messages), custom rules,
  selection and threshold overrides, scan roots and volumes, the scan, and
  the report — what `fclean scan --json` and `fclean config show --json`
  print, with no Python in the loop.
- `pyjson.rs` writes `json.dumps(indent=2, ensure_ascii=False)` exactly,
  including `repr(float)`.

*Done when:* the two reports are byte-identical to Python's, the port having
read the same config file for itself, across a matrix of configs.

*Result (2026-09-19):*

| Check | Outcome |
|---|---|
| JSON writer against `json.dumps`, 200,000 floats and 200,000 strings | identical, 9.0 MB |
| `config show --json`, real config | identical, 11,481 bytes |
| `scan --json ~`, real home, read-only | identical, 99,091 bytes (99,426 with `--include-disabled`) |
| Fixture matrix in CI (`tests/test_port_parity.py`): no config file / a config with custom rules, overrides, thresholds, keep-paths, explicit roots and an unknown key × defaults / `--include-disabled` / `--rules` / `--exclude`; a root that is not home; unreadable folders | identical, every cell |
| Bad configs and unknown rule ids | refused by both, in the same words |

Two things the gate is *not*: `duration_seconds` is wall-clock time and is
blanked on both sides; and the reference is Python **with the native walker**,
whose results come in a defined order (the pure-Python walk yields in
whatever order the filesystem lists — phase 1 compared against that one, as
sets).

*What the byte-level gate caught:* `repr(float)`. Rust and Python agree on
the shortest digits that round-trip except when a double lies exactly halfway
between two candidates (`827746655.84765625`): Rust rounds half up, Python
half to even. About one modification time in tens of thousands.

*Corrections to this plan, found while doing it:*
- There are no builtin profiles, and a scan never reads one: `profile apply`
  merges a profile into `config.toml`. "Across every builtin profile" became
  the config matrix above. `profiles`, and the writing half of `config`
  (atomic save, `config set`/`keep`/`threshold`), move to **phase 5**, with
  the commands that use them: until the CLI is native nothing native would
  call them, so there would be nothing to prove them against.
- There is no `fclean rules`; rules are listed by `fclean config show`.

*Known intentional divergences:* a custom rule whose `label`, `category`,
`kind`… is not a string is refused (Python applies `str()` to it); `~user`
paths are refused by name (Python asks the password database); the detail
after "is not valid TOML:" is the Rust parser's; a TOML datetime under an
*unknown* key prints in TOML's spelling, not `isoformat()`'s. Unlike Python,
the port never creates a default `config.toml`, and `scan-json` writes no
audit-log entry — both arrive with the commands themselves.

### Phase 3 — read-only commands  *(done 2026-09-19)*
`filewalk` (128, walk already native) · `duplicates` find-only (199) ·
`largefiles` (50) · `leftovers` (171) · `plan` save/load/revalidate (153) ·
`audit` read side (89) · `backups` list (150).

SHA-256 must match Python's digests exactly (they are exposed in output).
*Done when:* each command's `--json` output matches Python's on real data, and
`plan.json` written by either implementation is accepted by the other.

*Shipped:* one Rust module per Python module — `filewalk.rs`, `largefiles.rs`,
`duplicates.rs`, `leftovers.rs`, `backups.rs`, `audit.rs`, `plan.rs` — behind
`fclean-walk large-files-json`, `duplicates-json`, `leftovers-json`,
`backups-list-json`, `audit-json`, `plan-save` and `plan-check-json`. Each
reads the config for itself, as phase 2's do. Nothing `fclean` runs calls
them, and nothing that *acts* on a finding is ported: `duplicates --apply`,
`leftovers --apply`, `backups clean` and `apply PLAN` are phase 4.
`plan-save` writes the one file it is asked to write; everything else writes
nothing (a test compares every mtime under the sandbox before and after).

*Measured* (`tools/port_parity.py large-files | duplicates | leftovers |
backups | audit | plan`, all read-only):

| Gate | Result |
|---|---|
| `large-files --json`, real home | identical, 5,257 bytes (Python 48.7 s, Rust 24.9 s) |
| `duplicates --json`, `~/Documents ~/Desktop ~/Downloads` (651,902 of the files there evicted to iCloud) | identical, 12,587 bytes (Python 17.5 s, Rust 10.6 s); 0 files downloaded |
| `leftovers --json`, each `--kind`, real `~/Library` | identical, 191,136 bytes |
| `audit --json`, real log: `--limit 50`, all of it, `--action` filters | identical; the whole log is 1,109,620 bytes |
| `clean --save-plan`, real home | the two plan files identical, 98,528 bytes; each implementation revalidates both the same way (98,320 bytes) |
| `backups list --json`, real machine | macOS refused both without Full Disk Access, in the same words; the listing itself is proven on fixtures only |
| Fixture matrix in CI (`tests/test_port_parity.py`, 37 tests): one file reached twice in every way, contents equal for 64 KiB and no further, XML and binary plists whole and damaged, an audit log with everything a line can be, a plan gone stale in each way it can, bad plans | identical, every cell; bad plans refused by both in the same words |

The reference for everything built on `filewalk` is Python **with the native
walker**: which name of a hard-linked file is reported is the walker's choice,
so the pure-Python walk is a different and equally valid answer. A silent
fallback to it is an error in the gate.

*What the byte-level gate caught:*
- **`st_mtime` has two spellings.** CPython adds the halves as floats
  (`sec + 1e-9 * nsec`); the helper divides the nanoseconds (`ns / 1e9`). They
  differ in the last bit for **27%** of times. Until now every printed mtime
  had come from the helper, so there had only ever been one. `leftovers`
  prints both — a file's own time is Python's, the newest time inside a
  folder is the helper's, and the larger of the two wins — so the port has
  both (`st_mtime`). And `dir_stats_many` asks the helper only when there is
  more than one folder: a lone folder's time is Python's. Ported as it is.
- **`sorted(paths)` is not `sorted(strings)`.** A `Path` compares part by
  part, so `/r/a/b` sorts before `/r/a-c/b` although `-` sorts before `/`.
  The order of a duplicate group's paths (`pypath::path_cmp`).
- **`suffix` and `stem`** are `posixpath.splitext` since Python 3.14: `.app`
  and `..app` have no suffix, `Foo.` has `.` (`pypath::splitext`). The port
  follows the Python it is compared with.
- **A plan file is `json.dumps(..., indent=2)`**, with `ensure_ascii` left on:
  `Café`, surrogate pairs beyond U+FFFF, and DEL escaped — unlike every
  `--json` report (`pyjson::dumps_ascii`).
- **`splitlines` and `strip`** end a line and strip it at more characters
  than `\n` and Unicode white space (U+2028, U+001C–U+001F…). An audit entry
  holding a raw U+2028 is two broken lines to both implementations.

*What the real-data gate caught, in Python:* the `duplicates` gate did not
finish. 651,902 files under `~/Documents` and `~/Desktop` had been evicted to
iCloud (`SF_DATALESS`), and reading one makes macOS download it: hashing them
blocks for hours and fills the disk. Fixed on both sides (1.7.2): a same-size
candidate that is not on this disk is never read — it wastes no space here,
so it is no duplicate worth finding. `large-files` and `scan` still count
such a file at its full logical size; that is a separate question.
Two more, found by the fixtures: a truncated XML plist escaped `plistlib` as
an `ExpatError` and took `backups list` or `leftovers` down (1.7.2:
`plists.load_dict`); and `leftovers` listed `~/Library/Containers` without
the retry of 1.6.1 (1.7.2).

*Known intentional divergences* — all stricter, none looser:
- Limits Python mishandles are refused by name: `large-files --top 0` (an
  `IndexError` in Python as soon as one file is found), and a negative
  `duplicates --top` or `audit --limit` (Python slices from the wrong end).
- A plan is read strictly. Python coerces (`int("12")`, `bool(0)`,
  `float("5.0")`, `str(12)`, `True == 1` for the version); the port takes
  what Python *writes* and refuses a hand-edited value of the wrong type.
  Error details after "is not valid JSON:" and "cannot read" are Rust's.
- `audit`: Python's reader creates the log and sets its mode on the way in;
  the port creates nothing, and a log that is not there reads as empty. A
  line holding `NaN`, `Infinity`, an integer beyond 64 bits, a lone
  surrogate or `-0` is read by Python and skipped or respelled here; File
  Cleaner writes none of them.
- `backups`: a `Device Name` or `Product Type` that is not text is treated as
  missing (Python prints whatever it found). A date is rounded to the
  microsecond half-up where `timedelta` rounds half-even.
- A damaged plist of any kind names nothing, which is what Python does too
  as of 1.7.2.
- A file name that is not Unicode is left out of `leftovers` and `backups`
  (Python prints it with surrogate escapes); APFS allows none.

### Phase 4 — everything that mutates  *(highest risk; last before the TUI)*
`quarantine` move/restore/purge/secure-purge (498) · `duplicates --apply` ·
`organize` apply/undo + `classify` (500) · `backups clean` · `schedule` (112).

`manifest.db` schema and `plan.json` stay **format-compatible in both
directions**, so a user can roll back to the Python tool at any point.
The resolving gate before every move, restore and purge is ported first and
tested against the table before any code that calls it exists.
*Done when:* the full quarantine/restore/purge test suite passes against the
Rust binary on fixtures **and** against a copy of a real `manifest.db`; a
restore performed by Python of an item quarantined by Rust (and vice versa)
round-trips.

### Phase 5 — CLI parity and the flip
`cli` (1443, 38 commands) · `profiles` (89) · `config`, writing half (atomic
save, `set`/`keep`/`threshold`) — moved here from phase 2, see there. Same
commands, flags, exit codes and `--json`
shapes; `./fclean` starts the Rust binary. Python remains installable as
`fclean-py` for one minor release as the rollback path.

### Phase 6 — TUI
`tui` (790) in `ratatui`. Last because it is the largest surface with the
least safety content, and everything it drives is already proven by then.

### Out of scope for v1 of the port
`device` (157, iOS via `pymobiledevice3`): experimental and unverified today.
Either shells out to an existing tool or is dropped from the Rust v1; decided
at phase 5.

## Stop conditions

Halt and reassess — do not push through — if:
- a safety-semantics divergence from Python cannot be closed **or** shown to be
  strictly stricter;
- `manifest.db` / `plan.json` compatibility in both directions cannot be kept
  (it is the rollback path);
- a phase needs its parity oracle weakened to pass.

## Layout

`native/fclean-walk` stays the single crate through phase 1 (it *is* the
engine). It becomes a workspace — `fclean-core` (library) plus the `fclean`
binary — at phase 2, when there is a second consumer of the library.
