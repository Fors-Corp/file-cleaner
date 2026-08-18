# File Cleaner

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

## Quick start

```bash
fclean doctor          # volumes, config, quarantine health, FileVault status — read-only
fclean scan             # what could be cleaned up, and how much space it'd free — read-only
fclean clean             # same, but with --apply it actually moves matches to quarantine
fclean tui                 # interactive browser: select items, see live disk usage, confirm
```

`scan` and `clean` (without `--apply`) never modify anything — they're always safe to run.

## How the safety net works

1. **Dry-run by default.** `clean` only *reports* what it would do unless you pass `--apply`.
2. **Quarantine, not deletion.** `--apply` moves matches into `~/.filecleaner/quarantine/<session>/`,
   preserving their original path structure. On the same volume this is an instant rename —
   no extra free space is needed, which matters if your disk is nearly full.
3. **Full manifest.** Every quarantined item is recorded in a local SQLite database
   (`quarantine/manifest.db`) with its original path, size, timestamp, matched rule, and a
   hash — enough to restore it precisely.
4. **Restore any time** within the retention window:
   ```bash
   fclean restore --session <id>          # everything from one clean run
   fclean restore --path "Downloads"       # anything whose original path matches
   fclean quarantine list                  # see what's in quarantine right now
   ```
5. **Purge is separate, explicit, and confirmed.** Nothing leaves quarantine on its own.
   ```bash
   fclean quarantine purge                 # purges only items past the retention window
   fclean quarantine purge --older-than 7  # custom age threshold
   fclean quarantine purge --all           # everything, regardless of age
   ```
   Each of these prints exactly what will be deleted and requires typing `yes` (or `--yes`
   to skip the prompt in scripts). `--secure` additionally overwrites file bytes before
   removal — see [Secure deletion](#secure-deletion-what-actually-works) below for why this
   is extra, not required, on this Mac.
6. **A hardcoded deny-list** (`safety.py`) blocks system paths (`/System`, `/usr`, `/bin`,
   `/Applications`, etc.) from ever being touched, no matter what a rule matches or how
   config is set. It cannot be weakened from config — only narrowed further.
7. **Full audit trail** — every scan/clean/restore/purge is appended to
   `~/.filecleaner/audit.log` (JSON lines, metadata only, never file contents).

## What gets cleaned

Run `fclean config show` to see every rule, its category, risk level, and whether it's
enabled. Roughly:

| Category | Examples | Default |
|---|---|---|
| Caches | `~/Library/Caches/*`, browser HTTP caches | on |
| Logs | `~/Library/Logs`, crash/diagnostic reports | on |
| Trash | `~/.Trash`, external drives' `.Trashes` | on |
| System junk | `.DS_Store` | on |
| Developer | Xcode DerivedData, npm/yarn/pnpm/pip/Homebrew caches | on |
| Developer (opt-in) | old `node_modules` (30+ days untouched) | **off** |
| Personal (opt-in) | old files in `~/Downloads` (90+ days) | **off** |

Opt-in categories are real cleanup options but require a judgment call about what's still
needed, so they're excluded from the default sweep. Enable one with:
```bash
fclean config enable dev_node_modules
```

Limit any `scan`/`clean` run to specific rules with `--rules id1,id2`, or see disabled
categories too with `--include-disabled`.

## Keeping specific things

```bash
fclean config keep ~/Projects/important-app/node_modules   # permanent — every future run
fclean config unkeep ~/Projects/important-app/node_modules # remove from the keep list
fclean clean --exclude ~/Downloads/tax-docs                # one-off, this run only
```

## Duplicates and large files (read-only)

```bash
fclean duplicates ~/Pictures --top 20     # groups of identical files by content hash
fclean large-files ~/ --top 50            # biggest files under a path
```

Neither command moves anything — review the output and use the TUI or `config keep` /
manual `mv` to act on it.

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
  and filenames can reveal personal information.

## Configuration

`~/.config/filecleaner/config.toml`, created on first run:

```toml
retention_days = 30
quarantine_dir = "/Users/you/.filecleaner/quarantine"   # can point anywhere, e.g. an external drive
protected_paths = []                                     # populated by `config keep`
scan_roots = []                                           # empty = home dir + external volumes
rule_overrides = {}                                        # rule_id -> true/false
hash_duplicates_max_bytes = 2000000000                       # skip hashing files bigger than this
```

Edit directly, or via `fclean config set <key> <value>` / `config enable|disable <rule-id>` /
`config keep|unkeep <path>`.

## Development

```bash
.venv/bin/pytest -v
```

All tests run against synthetic `tmp_path` sandboxes (via `tests/conftest.py`, which
redirects `Path.home()` and every config/data path) — never the real filesystem, and never
require a real iPhone or real MobileSync backups.

## Known limitations

- macOS only (Library/Caches conventions, `/Volumes`, `fdesetup`, etc.) — no Windows/Linux support.
- No general iOS file/cache browsing over cable — not possible without a jailbreak; see
  the device management section above for what's actually feasible.
- No native GUI app (SwiftUI) — the Textual TUI is the interactive interface for this pass.
- The `device` subcommands are unverified against real hardware (see above).
