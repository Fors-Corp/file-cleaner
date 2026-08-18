"""Typer-based CLI. Everything here is local-only — no network calls."""

import os
import subprocess
from pathlib import Path
from typing import List, Optional

import typer
from rich.console import Console
from rich.prompt import Confirm
from rich.table import Table

from filecleaner import __version__
from filecleaner import audit as audit_mod
from filecleaner import config as config_mod
from filecleaner import duplicates as duplicates_mod
from filecleaner import format as fmt
from filecleaner import quarantine as quarantine_mod
from filecleaner import rules as rules_mod
from filecleaner import safety
from filecleaner import scanner
from filecleaner import volumes as volumes_mod

app = typer.Typer(
    add_completion=False,
    no_args_is_help=True,
    help="Local, privacy-preserving disk cleanup with a quarantine-based safety net.",
)
quarantine_app = typer.Typer(no_args_is_help=True, help="Inspect or purge the quarantine safety net.")
config_app = typer.Typer(no_args_is_help=True, help="View or edit configuration and rules.")
app.add_typer(quarantine_app, name="quarantine")
app.add_typer(config_app, name="config")

console = Console()


@app.callback()
def main(
    version: bool = typer.Option(False, "--version", help="Show version and exit."),
) -> None:
    if version:
        console.print(f"filecleaner {__version__}")
        raise typer.Exit()


def _parse_rules_filter(rules_filter: Optional[str]) -> Optional[set]:
    return set(rules_filter.split(",")) if rules_filter else None


def _parse_excludes(exclude: Optional[List[str]]) -> tuple:
    return tuple(Path(p).expanduser() for p in exclude) if exclude else ()


def _print_scan_result(result, cfg) -> None:
    by_cat = result.by_category()
    table = Table(title="Cleanup candidates")
    table.add_column("Category")
    table.add_column("Items", justify="right")
    table.add_column("Size", justify="right")
    for cat, items in sorted(by_cat.items(), key=lambda kv: sum(c.size_bytes for c in kv[1]), reverse=True):
        table.add_row(cat, str(len(items)), fmt.human_size(sum(c.size_bytes for c in items)))
    console.print(table)
    console.print(
        f"[bold]Total reclaimable: {fmt.human_size(result.total_size)}[/bold] "
        f"across {len(result.candidates)} items"
    )
    if result.errors:
        console.print(f"[yellow]{len(result.errors)} paths skipped due to read errors (permissions, etc.)[/yellow]")

    console.print()
    for vol in volumes_mod.list_volumes():
        pct_used = (vol.used_bytes / vol.total_bytes * 100) if vol.total_bytes else 0
        console.print(f"  {vol.name}: {fmt.human_size(vol.free_bytes)} free / {fmt.human_size(vol.total_bytes)} ({pct_used:.0f}% used)")


def _print_quarantine_table(entries, title: str) -> None:
    table = Table(title=title)
    table.add_column("ID")
    table.add_column("Category")
    table.add_column("Size", justify="right")
    table.add_column("Quarantined at")
    table.add_column("Original path", overflow="fold")
    for e in entries:
        table.add_row(str(e.id), e.category, fmt.human_size(e.size_bytes), e.timestamp[:19], e.original_path)
    console.print(table)


@app.command()
def scan(
    rules: Optional[str] = typer.Option(None, "--rules", help="Comma-separated rule ids to limit the scan to."),
    include_disabled: bool = typer.Option(
        False, "--include-disabled", help="Also report opt-in / disabled-by-default categories."
    ),
    exclude: Optional[List[str]] = typer.Option(
        None, "--exclude", help="Path to exclude from this scan only (repeatable). Use `fclean config keep` "
        "to exclude a path permanently instead."
    ),
) -> None:
    """Read-only report of cleanup candidates. Never modifies anything."""
    cfg = config_mod.load_config()
    result = scanner.run_scan(
        cfg,
        only_rules=_parse_rules_filter(rules),
        include_disabled=include_disabled,
        extra_excludes=_parse_excludes(exclude),
    )
    _print_scan_result(result, cfg)
    audit_mod.log_action("scan", {"candidate_count": len(result.candidates), "total_size": result.total_size})


@app.command()
def clean(
    rules: Optional[str] = typer.Option(None, "--rules", help="Comma-separated rule ids to limit the clean to."),
    apply: bool = typer.Option(False, "--apply", help="Actually move matches to quarantine (default: dry-run)."),
    yes: bool = typer.Option(False, "--yes", "-y", help="Skip the confirmation prompt."),
    include_disabled: bool = typer.Option(False, "--include-disabled", help="Also include opt-in categories."),
    exclude: Optional[List[str]] = typer.Option(
        None, "--exclude", help="Path to exclude from this run only (repeatable). Use `fclean config keep` "
        "to exclude a path permanently instead."
    ),
) -> None:
    """Move matched junk into the local quarantine (restorable). Dry-run unless --apply is passed."""
    cfg = config_mod.load_config()
    result = scanner.run_scan(
        cfg,
        only_rules=_parse_rules_filter(rules),
        include_disabled=include_disabled,
        extra_excludes=_parse_excludes(exclude),
    )
    _print_scan_result(result, cfg)

    if not result.candidates:
        console.print("Nothing to clean.")
        return

    if not apply:
        console.print("\n[dim]Dry run only — nothing was moved. Re-run with --apply to quarantine these items.[/dim]")
        return

    if not yes:
        confirmed = Confirm.ask(
            f"\nMove {len(result.candidates)} items ({fmt.human_size(result.total_size)}) to quarantine? "
            f"(restorable for {cfg['retention_days']} days)"
        )
        if not confirmed:
            console.print("Cancelled.")
            raise typer.Exit()

    entries = quarantine_mod.quarantine_candidates(result.candidates, cfg)
    freed = sum(e.size_bytes for e in entries)
    console.print(f"[green]Quarantined {len(entries)} items ({fmt.human_size(freed)}).[/green]")
    if entries:
        console.print(f"Restore any time with: [bold]fclean restore --session {entries[0].session_id}[/bold]")


@app.command()
def restore(
    session: Optional[str] = typer.Option(None, "--session", help="Restore only this quarantine session."),
    path: Optional[str] = typer.Option(None, "--path", help="Substring to match against original paths."),
    ids: Optional[str] = typer.Option(None, "--ids", help="Comma-separated quarantine entry ids."),
    yes: bool = typer.Option(False, "--yes", "-y"),
) -> None:
    """Restore quarantined items to their original location."""
    cfg = config_mod.load_config()
    entries = quarantine_mod.list_entries(cfg, session_id=session)
    if path:
        entries = [e for e in entries if path in e.original_path]
    if ids:
        wanted = {int(x) for x in ids.split(",")}
        entries = [e for e in entries if e.id in wanted]

    if not entries:
        console.print("No matching quarantine entries.")
        raise typer.Exit()

    _print_quarantine_table(entries, title="Will restore")
    if not yes and not Confirm.ask(f"Restore {len(entries)} items to their original locations?"):
        console.print("Cancelled.")
        raise typer.Exit()

    restored = quarantine_mod.restore_entries([e.id for e in entries], cfg)
    console.print(f"[green]Restored {len(restored)} items.[/green]")


@quarantine_app.command("list")
def quarantine_list(session: Optional[str] = typer.Option(None, "--session")) -> None:
    """List everything currently sitting in quarantine."""
    cfg = config_mod.load_config()
    entries = quarantine_mod.list_entries(cfg, session_id=session)
    _print_quarantine_table(entries, title="Quarantine")
    console.print(f"Total: {len(entries)} items, {fmt.human_size(sum(e.size_bytes for e in entries))}")
    console.print(f"[dim]Retention: {cfg['retention_days']} days before items become eligible for purge.[/dim]")


@quarantine_app.command("purge")
def quarantine_purge(
    older_than: Optional[int] = typer.Option(None, "--older-than", help="Purge items older than N days."),
    all_: bool = typer.Option(False, "--all", help="Purge every quarantine item, regardless of age."),
    secure: bool = typer.Option(
        False,
        "--secure",
        help="Overwrite file bytes before deleting (belt-and-suspenders only — see `fclean doctor` "
        "for why this doesn't add a real guarantee on SSD storage beyond what FileVault already gives you).",
    ),
    yes: bool = typer.Option(False, "--yes", "-y"),
) -> None:
    """PERMANENTLY delete quarantined items. This is the only irreversible command."""
    cfg = config_mod.load_config()
    if all_:
        entries = quarantine_mod.list_entries(cfg)
    elif older_than is not None:
        entries = quarantine_mod.eligible_for_purge({**cfg, "retention_days": older_than})
    else:
        entries = quarantine_mod.eligible_for_purge(cfg)

    if not entries:
        console.print("Nothing eligible for purge.")
        raise typer.Exit()

    _print_quarantine_table(entries, title="Will PERMANENTLY delete")
    console.print("[bold red]This cannot be undone.[/bold red]")
    if secure:
        console.print(
            "[dim]--secure: overwriting bytes before removal. On this Mac's SSD this is belt-and-suspenders "
            "only, not a stronger guarantee than FileVault already provides.[/dim]"
        )
    if not yes:
        typed = typer.prompt("Type 'yes' to confirm permanent deletion")
        if typed.strip().lower() != "yes":
            console.print("Cancelled.")
            raise typer.Exit()

    purged = quarantine_mod.purge_entries([e.id for e in entries], cfg, secure=secure)
    console.print(
        f"[green]Permanently deleted {len(purged)} items ({fmt.human_size(sum(e.size_bytes for e in purged))}).[/green]"
    )


@app.command()
def duplicates(
    paths: Optional[List[str]] = typer.Argument(None, help="Directories to scan (default: home directory)."),
    top: int = typer.Option(30, "--top", help="Show the top N duplicate groups by wasted space."),
    min_size: int = typer.Option(4096, "--min-size", help="Ignore files smaller than this many bytes."),
) -> None:
    """Find duplicate files by content hash. Read-only — nothing is moved."""
    cfg = config_mod.load_config()
    roots = [Path(p).expanduser() for p in paths] if paths else [Path.home()]
    console.print(
        f"Scanning for duplicates under: {', '.join(str(r) for r in roots)} "
        "[dim](file bytes are hashed locally to compare them — never read for any other purpose, "
        "never transmitted anywhere)[/dim]"
    )
    groups = duplicates_mod.find_duplicates(roots, cfg, min_size_bytes=min_size, max_groups=top)
    if not groups:
        console.print("No duplicates found.")
        return

    table = Table(title=f"Top {len(groups)} duplicate groups by wasted space")
    table.add_column("Wasted", justify="right")
    table.add_column("Size each", justify="right")
    table.add_column("Copies", justify="right")
    table.add_column("Paths", overflow="fold")
    for g in groups:
        table.add_row(
            fmt.human_size(g.wasted_bytes),
            fmt.human_size(g.size_bytes),
            str(len(g.paths)),
            "\n".join(str(p) for p in g.paths),
        )
    console.print(table)
    console.print(f"[bold]Total wasted space: {fmt.human_size(sum(g.wasted_bytes for g in groups))}[/bold]")
    console.print("[dim]Nothing was moved. Use the TUI (`fclean tui`) to select specific copies to quarantine.[/dim]")


@app.command(name="large-files")
def large_files(
    paths: Optional[List[str]] = typer.Argument(None, help="Directories to scan (default: home directory)."),
    top: int = typer.Option(30, "--top"),
) -> None:
    """List the largest files under the given paths. Read-only."""
    cfg = config_mod.load_config()
    roots = [Path(p).expanduser() for p in paths] if paths else [Path.home()]
    extra_protected = config_mod.extra_protected_paths(cfg)

    results: List[tuple] = []
    for root in roots:
        for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
            base = Path(dirpath)
            dirnames[:] = [d for d in dirnames if not safety.is_protected(base / d, extra_protected=extra_protected)]
            for filename in filenames:
                file_path = base / filename
                try:
                    if file_path.is_symlink():
                        continue
                    size = file_path.stat().st_size
                except OSError:
                    continue
                results.append((size, file_path))

    results.sort(reverse=True, key=lambda t: t[0])
    table = Table(title=f"Top {min(top, len(results))} largest files")
    table.add_column("Size", justify="right")
    table.add_column("Path", overflow="fold")
    for size, file_path in results[:top]:
        table.add_row(fmt.human_size(size), str(file_path))
    console.print(table)


@app.command()
def doctor() -> None:
    """Show detected volumes, config, and quarantine health."""
    cfg = config_mod.load_config()
    console.print("[bold]File Cleaner — doctor[/bold]")
    console.print(f"Version: {__version__}")
    console.print(f"Config file: {config_mod.CONFIG_FILE}")
    console.print(f"Quarantine dir: {config_mod.get_quarantine_dir(cfg)}")
    console.print(f"Retention: {cfg['retention_days']} days")
    console.print("[dim]Network access: none. filecleaner never makes network calls or sends telemetry.[/dim]")

    try:
        fv = subprocess.run(
            ["fdesetup", "status"], capture_output=True, text=True, timeout=5
        ).stdout.strip()
    except (OSError, subprocess.SubprocessError):
        fv = "unknown"
    console.print(f"FileVault: {fv}")
    if fv.lower().startswith("filevault is on"):
        console.print(
            "[dim]Since FileVault is on, `quarantine purge` already makes data cryptographically "
            "unrecoverable the instant it's deleted — --secure overwrite is extra, not required.[/dim]\n"
        )
    else:
        console.print(
            "[dim]FileVault is off — deleted data may be recoverable with forensic tools until the "
            "underlying blocks are reused. Consider enabling FileVault in System Settings, or use "
            "`quarantine purge --secure` for a (best-effort, non-guaranteed on SSD) extra overwrite pass.[/dim]\n"
        )

    table = Table(title="Volumes")
    table.add_column("Name")
    table.add_column("Path")
    table.add_column("Used", justify="right")
    table.add_column("Free", justify="right")
    table.add_column("Total", justify="right")
    for vol in volumes_mod.list_volumes():
        table.add_row(
            vol.name, str(vol.path), fmt.human_size(vol.used_bytes), fmt.human_size(vol.free_bytes), fmt.human_size(vol.total_bytes)
        )
    console.print(table)

    count, size = quarantine_mod.quarantine_summary(cfg)
    console.print(f"\nQuarantine: {count} items, {fmt.human_size(size)}")
    enabled_rules = [r for r in rules_mod.BUILTIN_RULES if config_mod.is_rule_enabled(cfg, r.id, r.enabled_by_default)]
    console.print(f"Enabled rules: {len(enabled_rules)}/{len(rules_mod.BUILTIN_RULES)}")


@app.command()
def tui() -> None:
    """Launch the interactive terminal browser."""
    from filecleaner.tui import run_tui

    run_tui()


@config_app.command("show")
def config_show() -> None:
    cfg = config_mod.load_config()
    console.print(f"Config file: {config_mod.CONFIG_FILE}")
    for key, value in cfg.items():
        console.print(f"  {key}: {value}")

    table = Table(title="Rules")
    table.add_column("Rule id")
    table.add_column("Category")
    table.add_column("Enabled")
    table.add_column("Risk")
    table.add_column("Description", overflow="fold")
    for rule in rules_mod.BUILTIN_RULES:
        enabled = config_mod.is_rule_enabled(cfg, rule.id, rule.enabled_by_default)
        table.add_row(rule.id, rule.category, "yes" if enabled else "no", rule.risk, rule.description)
    console.print(table)


@config_app.command("enable")
def config_enable(rule_id: str) -> None:
    cfg = config_mod.load_config()
    if rule_id not in rules_mod.rules_by_id():
        console.print(f"[red]Unknown rule id: {rule_id}[/red]")
        raise typer.Exit(code=1)
    cfg.setdefault("rule_overrides", {})[rule_id] = True
    config_mod.save_config(cfg)
    console.print(f"Enabled rule: {rule_id}")


@config_app.command("disable")
def config_disable(rule_id: str) -> None:
    cfg = config_mod.load_config()
    if rule_id not in rules_mod.rules_by_id():
        console.print(f"[red]Unknown rule id: {rule_id}[/red]")
        raise typer.Exit(code=1)
    cfg.setdefault("rule_overrides", {})[rule_id] = False
    config_mod.save_config(cfg)
    console.print(f"Disabled rule: {rule_id}")


@config_app.command("keep")
def config_keep(path: str) -> None:
    """Permanently exclude a path from every future scan/clean, regardless of which rules match it."""
    cfg = config_mod.load_config()
    config_mod.add_keep_path(cfg, path)
    config_mod.save_config(cfg)
    console.print(f"Will always keep: {Path(path).expanduser()}")


@config_app.command("unkeep")
def config_unkeep(path: str) -> None:
    """Remove a path from the permanent keep list."""
    cfg = config_mod.load_config()
    removed = config_mod.remove_keep_path(cfg, path)
    config_mod.save_config(cfg)
    if removed:
        console.print(f"Removed from keep list: {Path(path).expanduser()}")
    else:
        console.print(f"[yellow]Not on the keep list: {Path(path).expanduser()}[/yellow]")


@config_app.command("set")
def config_set(key: str, value: str) -> None:
    cfg = config_mod.load_config()
    if key not in cfg:
        console.print(f"[red]Unknown config key: {key}[/red]")
        raise typer.Exit(code=1)
    current = cfg[key]
    if isinstance(current, bool):
        cfg[key] = value.lower() in ("1", "true", "yes")
    elif isinstance(current, int):
        cfg[key] = int(value)
    else:
        cfg[key] = value
    config_mod.save_config(cfg)
    console.print(f"Set {key} = {cfg[key]}")


if __name__ == "__main__":
    app()
