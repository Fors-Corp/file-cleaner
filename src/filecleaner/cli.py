"""Typer-based CLI. Everything here is local-only — no network calls.

Every command that mutates the filesystem is dry-run by default and only
acts with an explicit ``--apply``/``--yes`` (or a typed confirmation for the
one truly irreversible command, ``quarantine purge``). Every command also
accepts ``--json`` for machine-readable output, so the same engine that
powers this CLI can sit behind a script, a launchd job, or a native GUI
front-end without scraping human-formatted text.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import typer
from rich.console import Console
from rich.markup import escape as esc
from rich.prompt import Confirm
from rich.table import Table

from filecleaner import __version__, scanner
from filecleaner import audit as audit_mod
from filecleaner import backups as backups_mod
from filecleaner import config as config_mod
from filecleaner import device as device_mod
from filecleaner import duplicates as duplicates_mod
from filecleaner import format as fmt
from filecleaner import largefiles as largefiles_mod
from filecleaner import output as output_mod
from filecleaner import plan as plan_mod
from filecleaner import quarantine as quarantine_mod
from filecleaner import rules as rules_mod
from filecleaner import volumes as volumes_mod
from filecleaner.models import ActionResult, BackupInfo, QuarantineEntry, ScanResult

app = typer.Typer(
    add_completion=False,
    invoke_without_command=True,
    help="Local, privacy-preserving disk cleanup with a quarantine-based safety net.",
)
quarantine_app = typer.Typer(no_args_is_help=True, help="Inspect, restore, or purge the quarantine safety net.")
config_app = typer.Typer(no_args_is_help=True, help="View or edit configuration and rules.")
backups_app = typer.Typer(no_args_is_help=True, help="Manage local iPhone/iPad backups (from cable/Finder syncs).")
device_app = typer.Typer(
    no_args_is_help=True,
    help="[EXPERIMENTAL, UNVERIFIED] Manage a connected iPhone/iPad live, over USB. "
    "Built without a physical device available to test against — try `fclean device list` first.",
)
app.add_typer(quarantine_app, name="quarantine")
app.add_typer(config_app, name="config")
app.add_typer(backups_app, name="backups")
app.add_typer(device_app, name="device")

_NO_COLOR = bool(os.environ.get("NO_COLOR"))
console = Console(no_color=_NO_COLOR, highlight=False)
err_console = Console(stderr=True, no_color=_NO_COLOR, highlight=False)

RISK_STYLE = {"low": "green", "medium": "yellow", "high": "red"}


class CliError(Exception):
    """A user-facing error: caught by `_entrypoint` and printed without a
    traceback (see its docstring for why this is a plain Exception rather
    than a click.ClickException — Typer's dispatcher checks against its
    own private, vendored exception hierarchy, not click's public one, so
    subclassing the public class silently does not get caught there)."""

    def __init__(self, message: str, *, exit_code: int = 1) -> None:
        super().__init__(message)
        self.exit_code = exit_code


def _load_config() -> dict:
    warnings: list[str] = []
    try:
        cfg = config_mod.load_config(warnings=warnings)
    except config_mod.ConfigError as exc:
        raise CliError(f"Configuration error: {exc}") from exc
    for w in warnings:
        err_console.print(f"[yellow]Warning:[/yellow] {esc(w)}")
    unknown_overrides = rules_mod.unknown_override_ids(cfg)
    for rid in unknown_overrides:
        err_console.print(f"[yellow]Warning:[/yellow] rule_overrides has unknown rule id {esc(rid)!r} (typo?)")
    try:
        rules_mod.load_custom_rules(cfg)
    except rules_mod.RuleError as exc:
        raise CliError(f"Invalid custom rule in config: {exc}") from exc
    return cfg


def _parse_rules_filter(rules_filter: str | None) -> set | None:
    return {r.strip() for r in rules_filter.split(",") if r.strip()} if rules_filter else None


def _parse_excludes(exclude: list[str] | None) -> tuple:
    return tuple(Path(p).expanduser() for p in exclude) if exclude else ()


def _run_scan(
    cfg: dict,
    *,
    rules: str | None,
    include_disabled: bool,
    exclude: list[str] | None,
    show_progress: bool = True,
) -> ScanResult:
    try:
        only_rules = _parse_rules_filter(rules)
    except Exception as exc:  # defensive; splitting a string cannot really fail
        raise CliError(str(exc)) from exc

    progress = None
    if show_progress and sys.stderr.isatty():
        def progress(msg: str) -> None:  # noqa: E306
            err_console.print(f"[dim]{msg}[/dim]", end="\r")

    try:
        result = scanner.run_scan(
            cfg,
            only_rules=only_rules,
            include_disabled=include_disabled,
            extra_excludes=_parse_excludes(exclude),
            progress=progress,
        )
    except scanner.UnknownRuleError as exc:
        raise CliError(str(exc)) from exc
    if show_progress and sys.stderr.isatty():
        err_console.print(" " * 80, end="\r")
    return result


def _print_scan_result(result: ScanResult) -> None:
    table = Table(title="Cleanup candidates")
    table.add_column("Category")
    table.add_column("Items", justify="right")
    table.add_column("Size", justify="right")
    for cat, items in sorted(result.by_category().items(), key=lambda kv: sum(c.size_bytes for c in kv[1]), reverse=True):
        table.add_row(esc(cat), str(len(items)), fmt.human_size(sum(c.size_bytes for c in items)))
    console.print(table)
    console.print(
        f"[bold]Total reclaimable: {fmt.human_size(result.total_size)}[/bold] "
        f"across {len(result.candidates)} items (scanned in {result.duration_seconds:.1f}s)"
    )
    if result.overlaps_dropped:
        console.print(f"[dim]{result.overlaps_dropped} overlapping match(es) counted once.[/dim]")
    if result.errors:
        shown = result.errors[:5]
        console.print(f"[yellow]{len(result.errors)} path(s) skipped due to read errors:[/yellow]")
        for e in shown:
            console.print(f"  [dim]{esc(e)}[/dim]")
        if len(result.errors) > len(shown):
            console.print(f"  [dim]… and {len(result.errors) - len(shown)} more[/dim]")

    console.print()
    for vol in volumes_mod.list_volumes():
        console.print(f"  {esc(vol.name)}: {fmt.human_size(vol.free_bytes)} free / {fmt.human_size(vol.total_bytes)} ({vol.percent_used:.0f}% used)")


def _print_quarantine_table(entries: list[QuarantineEntry], title: str) -> None:
    table = Table(title=title)
    table.add_column("ID")
    table.add_column("Category")
    table.add_column("Size", justify="right")
    table.add_column("Quarantined at")
    table.add_column("Original path", overflow="fold")
    for e in entries:
        note = "" if e.is_available else " [red](unavailable)[/red]"
        table.add_row(str(e.id), esc(e.category), fmt.human_size(e.size_bytes), fmt.short_timestamp(e.timestamp), esc(e.original_path) + note)
    console.print(table)


def _print_action_result(result: ActionResult, verb: str) -> None:
    if result.entries:
        console.print(f"[green]{verb} {len(result.entries)} item(s) ({fmt.human_size(result.total_size)}).[/green]")
    if result.skipped:
        console.print(f"[yellow]{len(result.skipped)} item(s) skipped:[/yellow]")
        for s in result.skipped[:10]:
            console.print(f"  [dim]{esc(s.path)}: {esc(s.reason)}[/dim]")
        if len(result.skipped) > 10:
            console.print(f"  [dim]… and {len(result.skipped) - 10} more[/dim]")
    if not result.entries and not result.skipped:
        console.print("Nothing to do.")


def _confirm(message: str, *, yes: bool) -> bool:
    if yes:
        return True
    if not sys.stdin.isatty():
        raise CliError("Refusing to proceed without --yes: input is not an interactive terminal.")
    return Confirm.ask(message)


@app.callback()
def main(
    ctx: typer.Context,
    version: bool = typer.Option(False, "--version", is_eager=True, help="Show version and exit."),
) -> None:
    if version:
        console.print(f"filecleaner {__version__}")
        raise typer.Exit()
    if ctx.invoked_subcommand is None:
        console.print(ctx.get_help())
        raise typer.Exit()


# --------------------------------------------------------------------------
# scan / clean / apply / restore
# --------------------------------------------------------------------------


@app.command()
def scan(
    rules: str | None = typer.Option(None, "--rules", help="Comma-separated rule ids to limit the scan to."),
    include_disabled: bool = typer.Option(
        False, "--include-disabled", help="Also report opt-in / disabled-by-default categories."
    ),
    exclude: list[str] | None = typer.Option(
        None, "--exclude", help="Path to exclude from this scan only (repeatable). Use `fclean config keep` "
        "to exclude a path permanently instead."
    ),
    as_json: bool = typer.Option(False, "--json", help="Print machine-readable JSON instead of a table."),
) -> None:
    """Read-only report of cleanup candidates. Never modifies anything."""
    cfg = _load_config()
    result = _run_scan(cfg, rules=rules, include_disabled=include_disabled, exclude=exclude, show_progress=not as_json)
    if as_json:
        output_mod.emit(result)
    else:
        _print_scan_result(result)
    audit_mod.log_action("scan", {"candidate_count": len(result.candidates), "total_size": result.total_size})


@app.command()
def clean(
    rules: str | None = typer.Option(None, "--rules", help="Comma-separated rule ids to limit the clean to."),
    apply: bool = typer.Option(False, "--apply", help="Actually move matches to quarantine (default: dry-run)."),
    yes: bool = typer.Option(False, "--yes", "-y", help="Skip the confirmation prompt."),
    include_disabled: bool = typer.Option(False, "--include-disabled", help="Also include opt-in categories."),
    exclude: list[str] | None = typer.Option(
        None, "--exclude", help="Path to exclude from this run only (repeatable). Use `fclean config keep` "
        "to exclude a path permanently instead."
    ),
    save_plan: Path | None = typer.Option(
        None, "--save-plan", help="Write the exact candidate list to a JSON file instead of acting on it. "
        "Review it, then run `fclean apply <file>` to quarantine precisely those items."
    ),
    as_json: bool = typer.Option(False, "--json", help="Print machine-readable JSON instead of tables."),
) -> None:
    """Move matched junk into the local quarantine (restorable). Dry-run unless --apply is passed."""
    cfg = _load_config()
    result = _run_scan(cfg, rules=rules, include_disabled=include_disabled, exclude=exclude, show_progress=not as_json)
    if not as_json:
        _print_scan_result(result)

    if save_plan is not None:
        plan_obj = plan_mod.CleanupPlan.from_scan(result)
        plan_mod.save_plan(plan_obj, save_plan)
        if as_json:
            output_mod.emit({"plan_file": str(save_plan.expanduser()), **plan_obj.to_dict()})
        else:
            console.print(f"[green]Saved a plan for {len(plan_obj.candidates)} item(s) to {esc(str(save_plan))}.[/green]")
            console.print(f"Review it, then run: [bold]fclean apply {esc(str(save_plan))}[/bold]")
        return

    if not result.candidates:
        if as_json:
            output_mod.emit(ActionResult(action="quarantine"))
        else:
            console.print("Nothing to clean.")
        return

    if not apply:
        if as_json:
            output_mod.emit(result)
        else:
            console.print("\n[dim]Dry run only — nothing was moved. Re-run with --apply to quarantine these items.[/dim]")
        return

    if not _confirm(
        f"\nMove {len(result.candidates)} items ({fmt.human_size(result.total_size)}) to quarantine? "
        f"(restorable for {cfg['retention_days']} days)",
        yes=yes,
    ):
        console.print("Cancelled.")
        raise typer.Exit()

    action = quarantine_mod.quarantine_candidates(result.candidates, cfg, allowed_roots=tuple(result.scan_roots))
    if as_json:
        output_mod.emit(action)
    else:
        _print_action_result(action, "Quarantined")
        if action.entries:
            console.print(f"Restore any time with: [bold]fclean restore --session {action.session_id}[/bold]")


@app.command()
def apply(
    plan_file: Path = typer.Argument(..., help="A plan file written by `fclean clean --save-plan`."),
    yes: bool = typer.Option(False, "--yes", "-y"),
    as_json: bool = typer.Option(False, "--json"),
) -> None:
    """Quarantine exactly the items listed in a previously saved plan.

    Every item is re-checked against the filesystem first: anything that no
    longer exists, changed size, or changed kind (file/dir) since the plan
    was written is skipped and reported, never silently substituted.
    """
    try:
        plan_obj = plan_mod.load_plan(plan_file)
    except plan_mod.PlanError as exc:
        raise CliError(str(exc)) from exc

    cfg = _load_config()
    fresh, stale = plan_mod.revalidate(plan_obj)
    if not as_json:
        console.print(f"Plan from {plan_obj.created_at}: {len(plan_obj.candidates)} item(s), {fmt.human_size(plan_obj.total_size)}")
        if stale:
            console.print(f"[yellow]{len(stale)} item(s) changed since the plan was written and will be skipped:[/yellow]")
            for s in stale[:10]:
                console.print(f"  [dim]{esc(s.path)}: {esc(s.reason)}[/dim]")
    if not fresh:
        if as_json:
            output_mod.emit(ActionResult(action="quarantine", skipped=stale))
        else:
            console.print("Nothing left to apply.")
        return

    if not _confirm(f"\nMove {len(fresh)} item(s) to quarantine?", yes=yes):
        console.print("Cancelled.")
        raise typer.Exit()

    action = quarantine_mod.quarantine_candidates(fresh, cfg, allowed_roots=tuple(plan_obj.scan_roots))
    action.skipped = stale + action.skipped
    if as_json:
        output_mod.emit(action)
    else:
        _print_action_result(action, "Quarantined")
        if action.entries:
            console.print(f"Restore any time with: [bold]fclean restore --session {action.session_id}[/bold]")


@app.command()
def restore(
    session: str | None = typer.Option(None, "--session", help="Restore only this quarantine session."),
    path: str | None = typer.Option(None, "--path", help="Substring to match against original paths."),
    ids: str | None = typer.Option(None, "--ids", help="Comma-separated quarantine entry ids."),
    yes: bool = typer.Option(False, "--yes", "-y"),
    as_json: bool = typer.Option(False, "--json"),
) -> None:
    """Restore quarantined items to their original location."""
    cfg = _load_config()
    id_filter = None
    if ids:
        try:
            id_filter = tuple(int(x) for x in ids.split(","))
        except ValueError as exc:
            raise CliError(f"--ids must be a comma-separated list of integers: {exc}") from exc

    entries = quarantine_mod.list_entries(cfg, session_id=session, path_contains=path, ids=id_filter)
    if not entries:
        if as_json:
            output_mod.emit(ActionResult(action="restore"))
        else:
            console.print("No matching quarantine entries.")
        raise typer.Exit()

    if not as_json:
        _print_quarantine_table(entries, title="Will restore")
    if not _confirm(f"Restore {len(entries)} items to their original locations?", yes=yes):
        console.print("Cancelled.")
        raise typer.Exit()

    action = quarantine_mod.restore_entries([e.id for e in entries], cfg)
    if as_json:
        output_mod.emit(action)
    else:
        _print_action_result(action, "Restored")


# --------------------------------------------------------------------------
# quarantine subcommand
# --------------------------------------------------------------------------


@quarantine_app.command("list")
def quarantine_list(
    session: str | None = typer.Option(None, "--session"),
    as_json: bool = typer.Option(False, "--json"),
) -> None:
    """List everything currently sitting in quarantine."""
    cfg = _load_config()
    entries = quarantine_mod.list_entries(cfg, session_id=session)
    if as_json:
        output_mod.emit({"entries": [e.to_dict() for e in entries], "total_size_bytes": sum(e.size_bytes for e in entries)})
        return
    _print_quarantine_table(entries, title="Quarantine")
    console.print(f"Total: {len(entries)} items, {fmt.human_size(sum(e.size_bytes for e in entries))}")
    console.print(f"[dim]Retention: {cfg['retention_days']} days before items become eligible for purge.[/dim]")


@quarantine_app.command("sessions")
def quarantine_sessions(as_json: bool = typer.Option(False, "--json")) -> None:
    """List quarantine sessions (one per `clean --apply` / `apply` run)."""
    cfg = _load_config()
    sessions = quarantine_mod.list_sessions(cfg)
    if as_json:
        output_mod.emit({"sessions": [s.to_dict() for s in sessions]})
        return
    table = Table(title="Quarantine sessions")
    table.add_column("Session")
    table.add_column("Items", justify="right")
    table.add_column("Size", justify="right")
    table.add_column("First quarantined")
    for s in sessions:
        table.add_row(s.session_id, str(s.count), fmt.human_size(s.size_bytes), fmt.short_timestamp(s.first_timestamp))
    console.print(table)


@quarantine_app.command("purge")
def quarantine_purge(
    older_than: int | None = typer.Option(None, "--older-than", help="Purge items older than N days."),
    all_: bool = typer.Option(False, "--all", help="Purge every quarantine item, regardless of age."),
    session: str | None = typer.Option(None, "--session", help="Purge only items from this session."),
    secure: bool = typer.Option(
        False,
        "--secure",
        help="Overwrite file bytes before deleting (belt-and-suspenders only — see `fclean doctor` "
        "for why this doesn't add a real guarantee on SSD storage beyond what FileVault already gives you).",
    ),
    yes: bool = typer.Option(False, "--yes", "-y"),
    as_json: bool = typer.Option(False, "--json"),
) -> None:
    """PERMANENTLY delete quarantined items. This is the only irreversible command."""
    cfg = _load_config()
    if session is not None:
        entries = quarantine_mod.list_entries(cfg, session_id=session)
    elif all_:
        entries = quarantine_mod.list_entries(cfg)
    elif older_than is not None:
        entries = quarantine_mod.eligible_for_purge({**cfg, "retention_days": older_than})
    else:
        entries = quarantine_mod.eligible_for_purge(cfg)

    if not entries:
        if as_json:
            output_mod.emit(ActionResult(action="purge"))
        else:
            console.print("Nothing eligible for purge.")
        raise typer.Exit()

    if not as_json:
        _print_quarantine_table(entries, title="Will PERMANENTLY delete")
        console.print("[bold red]This cannot be undone.[/bold red]")
        if secure:
            console.print(
                "[dim]--secure: overwriting bytes before removal. On SSD storage this is belt-and-suspenders "
                "only, not a stronger guarantee than FileVault already provides.[/dim]"
            )
    if not yes:
        if not sys.stdin.isatty():
            raise CliError("Refusing to purge without --yes: input is not an interactive terminal.")
        typed = typer.prompt("Type 'yes' to confirm permanent deletion")
        if typed.strip().lower() != "yes":
            console.print("Cancelled.")
            raise typer.Exit()

    action = quarantine_mod.purge_entries([e.id for e in entries], cfg, secure=secure)
    if as_json:
        output_mod.emit(action)
    else:
        _print_action_result(action, "Permanently deleted")


# --------------------------------------------------------------------------
# duplicates / large-files (read-only)
# --------------------------------------------------------------------------


@app.command()
def duplicates(
    paths: list[str] | None = typer.Argument(None, help="Directories to scan (default: home directory)."),
    top: int = typer.Option(30, "--top", help="Show the top N duplicate groups by wasted space."),
    min_size: int = typer.Option(4096, "--min-size", help="Ignore files smaller than this many bytes."),
    as_json: bool = typer.Option(False, "--json"),
) -> None:
    """Find duplicate files by content hash. Read-only — nothing is moved."""
    cfg = _load_config()
    roots = [Path(p).expanduser() for p in paths] if paths else [Path.home()]
    if not as_json:
        console.print(
            f"Scanning for duplicates under: {', '.join(esc(str(r)) for r in roots)} "
            "[dim](file bytes are hashed locally to compare them — never read for any other purpose, "
            "never transmitted anywhere)[/dim]"
        )
    progress = (lambda msg: err_console.print(f"[dim]{msg}[/dim]", end="\r")) if (not as_json and sys.stderr.isatty()) else None
    groups = duplicates_mod.find_duplicates(roots, cfg, min_size_bytes=min_size, max_groups=top, progress=progress)
    if progress:
        err_console.print(" " * 80, end="\r")

    if as_json:
        output_mod.emit({"groups": [g.to_dict() for g in groups], "total_wasted_bytes": sum(g.wasted_bytes for g in groups)})
        return
    if not groups:
        console.print("No duplicates found.")
        return

    table = Table(title=f"Top {len(groups)} duplicate groups by wasted space")
    table.add_column("Wasted", justify="right")
    table.add_column("Size each", justify="right")
    table.add_column("Copies", justify="right")
    table.add_column("Paths", overflow="fold")
    for g in groups:
        table.add_row(fmt.human_size(g.wasted_bytes), fmt.human_size(g.size_bytes), str(len(g.paths)), "\n".join(esc(str(p)) for p in g.paths))
    console.print(table)
    console.print(f"[bold]Total wasted space: {fmt.human_size(sum(g.wasted_bytes for g in groups))}[/bold]")
    console.print("[dim]Nothing was moved. Use the TUI (`fclean tui`) or `config keep` / manual `mv` to act on it.[/dim]")


@app.command(name="large-files")
def large_files(
    paths: list[str] | None = typer.Argument(None, help="Directories to scan (default: home directory)."),
    top: int = typer.Option(30, "--top"),
    min_size: int = typer.Option(0, "--min-size", help="Ignore files smaller than this many bytes."),
    as_json: bool = typer.Option(False, "--json"),
) -> None:
    """List the largest files under the given paths. Read-only."""
    cfg = _load_config()
    roots = [Path(p).expanduser() for p in paths] if paths else [Path.home()]
    progress = (lambda msg: err_console.print(f"[dim]{msg}[/dim]", end="\r")) if (not as_json and sys.stderr.isatty()) else None
    results = largefiles_mod.find_large_files(roots, cfg, top=top, min_size_bytes=min_size, progress=progress)
    if progress:
        err_console.print(" " * 80, end="\r")

    if as_json:
        output_mod.emit({"files": [f.to_dict() for f in results]})
        return
    table = Table(title=f"Top {len(results)} largest files")
    table.add_column("Size", justify="right")
    table.add_column("Age")
    table.add_column("Path", overflow="fold")
    for f in results:
        table.add_row(fmt.human_size(f.size_bytes), fmt.human_age(f.mtime), esc(str(f.path)))
    console.print(table)


# --------------------------------------------------------------------------
# backups
# --------------------------------------------------------------------------


def _print_backups_table(backups: list[BackupInfo], title: str) -> None:
    table = Table(title=title)
    table.add_column("Device")
    table.add_column("Type")
    table.add_column("Last backup")
    table.add_column("Size", justify="right")
    table.add_column("Encrypted")
    for b in sorted(backups, key=lambda b: b.size_bytes, reverse=True):
        last = b.last_backup_date.strftime("%Y-%m-%d %H:%M") if b.last_backup_date else "unknown"
        table.add_row(esc(b.device_name), esc(b.product_type or "?"), last, fmt.human_size(b.size_bytes), "yes" if b.encrypted else "no")
    console.print(table)


@backups_app.command("list")
def backups_list(as_json: bool = typer.Option(False, "--json")) -> None:
    """List local iPhone/iPad backups under ~/Library/Application Support/MobileSync/Backup."""
    try:
        found = backups_mod.find_backups()
    except backups_mod.BackupAccessDenied as exc:
        raise CliError(str(exc)) from exc

    if as_json:
        output_mod.emit({"backups": [b.to_dict() for b in found]})
        return
    if not found:
        console.print("No local iPhone/iPad backups found.")
        return
    _print_backups_table(found, title="iPhone/iPad backups")
    console.print(f"Total: {fmt.human_size(sum(b.size_bytes for b in found))}")


@backups_app.command("clean")
def backups_clean(
    keep_latest: int = typer.Option(1, "--keep-latest", help="Always keep this many most-recent backups per device."),
    older_than: int | None = typer.Option(
        None, "--older-than", help="Only consider backups at least this many days old."
    ),
    apply: bool = typer.Option(False, "--apply", help="Actually move stale backups to quarantine (default: dry-run)."),
    yes: bool = typer.Option(False, "--yes", "-y"),
    as_json: bool = typer.Option(False, "--json"),
) -> None:
    """Move stale iPhone/iPad backups into quarantine. Always keeps the most recent backup per device."""
    cfg = _load_config()
    try:
        found = backups_mod.find_backups()
    except backups_mod.BackupAccessDenied as exc:
        raise CliError(str(exc)) from exc

    stale = backups_mod.stale_backups(found, keep_latest_per_device=keep_latest, older_than_days=older_than)
    if not stale:
        if as_json:
            output_mod.emit(ActionResult(action="quarantine"))
        else:
            console.print(f"Nothing stale — {len(found)} backup(s) found, all within the keep-latest-{keep_latest} window.")
        return

    total = sum(b.size_bytes for b in stale)
    if not as_json:
        _print_backups_table(stale, title="Stale backups (candidates for quarantine)")
        console.print(f"[bold]Total reclaimable: {fmt.human_size(total)}[/bold]")

    if not apply:
        if as_json:
            output_mod.emit({"backups": [b.to_dict() for b in stale], "total_size_bytes": total})
        else:
            console.print("\n[dim]Dry run only — nothing was moved. Re-run with --apply to quarantine these backups.[/dim]")
        return

    if not _confirm(
        f"\nMove {len(stale)} backup(s) ({fmt.human_size(total)}) to quarantine? "
        f"(restorable for {cfg['retention_days']} days)",
        yes=yes,
    ):
        console.print("Cancelled.")
        raise typer.Exit()

    candidates = [backups_mod.to_candidate(b) for b in stale]
    action = quarantine_mod.quarantine_candidates(candidates, cfg)
    if as_json:
        output_mod.emit(action)
    else:
        _print_action_result(action, "Quarantined")


# --------------------------------------------------------------------------
# device (experimental)
# --------------------------------------------------------------------------


@device_app.command("list")
def device_list(as_json: bool = typer.Option(False, "--json")) -> None:
    """[EXPERIMENTAL] List iOS devices connected over USB."""
    try:
        found = device_mod.list_devices()
    except device_mod.DeviceUnavailable as exc:
        raise CliError(str(exc)) from exc

    if as_json:
        output_mod.emit({"devices": [{"udid": d.udid, "name": d.name, "product_type": d.product_type} for d in found]})
        return
    if not found:
        console.print("No iOS devices connected.")
        return
    table = Table(title="Connected iOS devices")
    table.add_column("Name")
    table.add_column("Product type")
    table.add_column("UDID")
    for d in found:
        table.add_row(esc(d.name), esc(d.product_type), esc(d.udid))
    console.print(table)


@device_app.command("apps")
def device_apps(
    udid: str | None = typer.Option(None, "--udid", help="Target a specific device (default: first connected)."),
    all_apps: bool = typer.Option(False, "--all", help="Include system apps, not just user-installed ones."),
    as_json: bool = typer.Option(False, "--json"),
) -> None:
    """[EXPERIMENTAL] List installed apps and their on-device storage usage."""
    try:
        apps = device_mod.list_apps(udid, user_apps_only=not all_apps)
    except device_mod.DeviceUnavailable as exc:
        raise CliError(str(exc)) from exc

    if as_json:
        output_mod.emit(
            {"apps": [{"bundle_id": a.bundle_id, "name": a.name, "version": a.version, "size_bytes": a.size_bytes} for a in apps]}
        )
        return
    if not apps:
        console.print("No apps found.")
        return
    table = Table(title="Installed apps")
    table.add_column("App")
    table.add_column("Version")
    table.add_column("Size", justify="right")
    table.add_column("Bundle ID")
    for a in sorted(apps, key=lambda a: a.size_bytes, reverse=True):
        table.add_row(esc(a.name), esc(a.version), fmt.human_size(a.size_bytes), esc(a.bundle_id))
    console.print(table)
    console.print(f"Total: {fmt.human_size(sum(a.size_bytes for a in apps))}")


@device_app.command("uninstall")
def device_uninstall(
    bundle_id: str,
    udid: str | None = typer.Option(None, "--udid"),
    yes: bool = typer.Option(False, "--yes", "-y"),
) -> None:
    """[EXPERIMENTAL] Uninstall an app from the connected device.

    This removes the app AND its on-device data. Unlike everything else in
    fclean, this does not go through the local quarantine — there's no
    "restore" for a device uninstall short of reinstalling the app fresh
    from the App Store. Confirmation is required.
    """
    if not _confirm(
        f"Uninstall {bundle_id} from the device? This removes its on-device data too "
        "and cannot be undone by fclean.",
        yes=yes,
    ):
        console.print("Cancelled.")
        raise typer.Exit()

    try:
        device_mod.uninstall_app(bundle_id, udid)
    except device_mod.DeviceUnavailable as exc:
        raise CliError(str(exc)) from exc

    console.print(f"[green]Uninstalled {esc(bundle_id)}.[/green]")
    audit_mod.log_action("device_uninstall", {"bundle_id": bundle_id, "udid": udid})


# --------------------------------------------------------------------------
# doctor / audit / tui
# --------------------------------------------------------------------------


@app.command()
def doctor(as_json: bool = typer.Option(False, "--json")) -> None:
    """Show detected volumes, config health, and quarantine status."""
    warnings: list[str] = []
    try:
        cfg = config_mod.load_config(warnings=warnings)
    except config_mod.ConfigError as exc:
        raise CliError(f"Configuration error: {exc}") from exc
    warnings += [f"rule_overrides has unknown rule id {rid!r} (typo?)" for rid in rules_mod.unknown_override_ids(cfg)]
    rule_error: str | None = None
    try:
        custom_rules = rules_mod.load_custom_rules(cfg)
    except rules_mod.RuleError as exc:
        custom_rules = []
        rule_error = str(exc)

    try:
        fv_status = subprocess.run(["fdesetup", "status"], capture_output=True, text=True, timeout=5).stdout.strip()
    except (OSError, subprocess.SubprocessError):
        fv_status = "unknown"
    filevault_on = fv_status.lower().startswith("filevault is on")

    volumes = volumes_mod.list_volumes()
    count, size = quarantine_mod.overall_summary(cfg)
    enabled_rules = [r for r in rules_mod.all_rules(cfg) if config_mod.is_rule_enabled(cfg, r.id, r.enabled_by_default)]

    if as_json:
        output_mod.emit(
            {
                "version": __version__,
                "config_file": str(config_mod.CONFIG_FILE),
                "quarantine_dir": str(config_mod.get_quarantine_dir(cfg)),
                "retention_days": cfg["retention_days"],
                "filevault": fv_status,
                "filevault_on": filevault_on,
                "volumes": [v.to_dict() for v in volumes],
                "quarantine_items": count,
                "quarantine_bytes": size,
                "rules_enabled": len(enabled_rules),
                "rules_total": len(rules_mod.all_rules(cfg)),
                "custom_rules": len(custom_rules),
                "warnings": warnings + ([rule_error] if rule_error else []),
            }
        )
        return

    console.print("[bold]File Cleaner — doctor[/bold]")
    console.print(f"Version: {__version__}")
    console.print(f"Config file: {esc(str(config_mod.CONFIG_FILE))}")
    console.print(f"Quarantine dir: {esc(str(config_mod.get_quarantine_dir(cfg)))}")
    console.print(f"Retention: {cfg['retention_days']} days")
    console.print("[dim]Network access: none. File Cleaner never makes network calls or sends telemetry.[/dim]")
    for w in warnings:
        console.print(f"[yellow]Warning: {esc(w)}[/yellow]")
    if rule_error:
        console.print(f"[red]Custom rules disabled: {esc(rule_error)}[/red]")

    console.print(f"FileVault: {esc(fv_status)}")
    if filevault_on:
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
    for vol in volumes:
        table.add_row(esc(vol.name), esc(str(vol.path)), fmt.human_size(vol.used_bytes), fmt.human_size(vol.free_bytes), fmt.human_size(vol.total_bytes))
    console.print(table)

    console.print(f"\nQuarantine: {count} items, {fmt.human_size(size)}")
    console.print(f"Enabled rules: {len(enabled_rules)}/{len(rules_mod.all_rules(cfg))}" + (f" ({len(custom_rules)} custom)" if custom_rules else ""))


@app.command()
def audit(
    limit: int = typer.Option(50, "--limit", help="Show at most this many recent entries."),
    action: str | None = typer.Option(None, "--action", help="Filter to one action type, e.g. purge."),
    as_json: bool = typer.Option(False, "--json"),
) -> None:
    """Show the local audit log — every scan/clean/restore/purge this tool has run."""
    entries = audit_mod.read_audit_log(limit=limit, action=action)
    if as_json:
        output_mod.emit({"entries": entries})
        return
    if not entries:
        console.print("Audit log is empty.")
        return
    table = Table(title=f"Audit log (last {len(entries)})")
    table.add_column("Timestamp")
    table.add_column("Action")
    table.add_column("Detail", overflow="fold")
    for e in entries:
        ts = str(e.get("timestamp", ""))[:19].replace("T", " ")
        act = str(e.get("action", ""))
        detail = ", ".join(f"{k}={v}" for k, v in e.items() if k not in ("timestamp", "action"))
        table.add_row(ts, esc(act), esc(detail))
    console.print(table)


@app.command()
def tui() -> None:
    """Launch the interactive terminal browser."""
    from filecleaner.tui import run_tui

    run_tui()


# --------------------------------------------------------------------------
# config
# --------------------------------------------------------------------------


@config_app.command("show")
def config_show(as_json: bool = typer.Option(False, "--json")) -> None:
    cfg = _load_config()
    if as_json:
        output_mod.emit(
            {
                "config_file": str(config_mod.CONFIG_FILE),
                "config": cfg,
                "rules": [
                    {**r.to_dict(), "enabled": config_mod.is_rule_enabled(cfg, r.id, r.enabled_by_default)}
                    for r in rules_mod.all_rules(cfg)
                ],
            }
        )
        return
    console.print(f"Config file: {esc(str(config_mod.CONFIG_FILE))}")
    for key, (_default, _validator, desc) in config_mod.CONFIG_SCHEMA.items():
        console.print(f"  {esc(key)}: {esc(str(cfg.get(key)))}  [dim]{esc(desc)}[/dim]")

    table = Table(title="Rules")
    table.add_column("Rule id")
    table.add_column("Category")
    table.add_column("Enabled")
    table.add_column("Risk")
    table.add_column("Description", overflow="fold")
    for rule in rules_mod.all_rules(cfg):
        enabled = config_mod.is_rule_enabled(cfg, rule.id, rule.enabled_by_default)
        risk_style = RISK_STYLE.get(rule.risk, "")
        table.add_row(
            esc(rule.id) + (" [dim](custom)[/dim]" if rule.source == "custom" else ""),
            esc(rule.category),
            "yes" if enabled else "no",
            f"[{risk_style}]{esc(rule.risk)}[/{risk_style}]" if risk_style else esc(rule.risk),
            esc(rule.description),
        )
    console.print(table)


@config_app.command("enable")
def config_enable(rule_id: str) -> None:
    cfg = _load_config()
    if rule_id not in rules_mod.rules_by_id(cfg):
        raise CliError(f"Unknown rule id: {rule_id}")
    cfg.setdefault("rule_overrides", {})[rule_id] = True
    config_mod.save_config(cfg)
    console.print(f"Enabled rule: {esc(rule_id)}")


@config_app.command("disable")
def config_disable(rule_id: str) -> None:
    cfg = _load_config()
    if rule_id not in rules_mod.rules_by_id(cfg):
        raise CliError(f"Unknown rule id: {rule_id}")
    cfg.setdefault("rule_overrides", {})[rule_id] = False
    config_mod.save_config(cfg)
    console.print(f"Disabled rule: {esc(rule_id)}")


@config_app.command("keep")
def config_keep(path: str) -> None:
    """Permanently exclude a path from every future scan/clean, regardless of which rules match it."""
    cfg = _load_config()
    config_mod.add_keep_path(cfg, path)
    config_mod.save_config(cfg)
    console.print(f"Will always keep: {esc(str(Path(path).expanduser()))}")


@config_app.command("unkeep")
def config_unkeep(path: str) -> None:
    """Remove a path from the permanent keep list."""
    cfg = _load_config()
    removed = config_mod.remove_keep_path(cfg, path)
    config_mod.save_config(cfg)
    if removed:
        console.print(f"Removed from keep list: {esc(str(Path(path).expanduser()))}")
    else:
        console.print(f"[yellow]Not on the keep list: {esc(str(Path(path).expanduser()))}[/yellow]")


@config_app.command("set")
def config_set(key: str, value: str) -> None:
    cfg = _load_config()
    try:
        parsed = config_mod.set_value(cfg, key, value)
    except config_mod.ConfigError as exc:
        raise CliError(str(exc)) from exc
    config_mod.save_config(cfg)
    console.print(f"Set {esc(key)} = {esc(str(parsed))}")


def _entrypoint() -> None:
    """The real `fclean` entry point: prints CliError cleanly (no traceback)
    and maps it to a process exit code. Tests that invoke `app` directly
    through Typer's CliRunner bypass this — CliRunner reports an uncaught
    CliError via `result.exception` instead, which is the supported way to
    assert on it there."""
    try:
        app()
    except CliError as exc:
        err_console.print(f"[red]Error:[/red] {esc(str(exc))}")
        raise SystemExit(exc.exit_code) from None
    except KeyboardInterrupt:
        err_console.print("\n[yellow]Interrupted.[/yellow]")
        raise SystemExit(130) from None


if __name__ == "__main__":
    _entrypoint()
