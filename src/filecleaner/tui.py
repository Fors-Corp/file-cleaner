"""Interactive terminal browser: an ncdu-style view over cleanup candidates,
plus Rules/Profiles/Stats/Organize tabs for customization, history, and
smart folder reorganization.

Accessibility & responsiveness notes
-------------------------------------
* Every action has a visible keybinding shown in the footer (Textual
  renders this automatically from ``BINDINGS``); nothing requires a mouse.
* Risk and status are never color-only: labels always carry text
  (``[low]``/``[medium]``/``[high]``, "restore", "quarantine") alongside
  any color, so the app remains usable with color off (``NO_COLOR=1``) or
  under a color-blind palette.
* Textual's ``SelectionList``/``DataTable`` reflow to the terminal size
  automatically; there is no fixed-width layout here, so resizing the
  terminal (or running in a narrow pane) never clips content — text wraps
  or scrolls instead.
* Nothing is quarantined without an explicit selection plus a confirmation
  dialog that states exactly how many items and how many bytes — there is
  no "select all and go" default.
* Long-running scans run in a background worker (``@work``) so the UI
  stays responsive and announces progress instead of freezing.

Correctness note: every label built here embeds a real filesystem path or
a rule category, neither of which this tool controls — a folder can be
named literally ``[Beta]`` or ``App [1.2]``. Textual's own markup parser
silently *drops* a bracketed run that happens to look like a tag (e.g. a
single word in brackets), which would misrepresent — or entirely hide part
of — the exact path about to be moved. All such content is therefore
wrapped in ``rich.text.Text`` (never a bare ``str``), which Textual renders
as literal text with no markup parsing at all.

Tab layout: the main screen is a ``TabbedContent`` (Scan / Rules / Profiles
/ Stats / Organize). All tabs are mounted at once — Textual keeps inactive
``TabPane`` content in the DOM and just hides it — so widget ids like
``#candidates``/``#status`` stay queryable regardless of which tab is
active. The Quarantine view stays a separate pushed ``Screen`` (unchanged),
reachable with "u" from any tab.

The Organize tab lists ``organize.propose_moves()``'s suggestions for the
same root the Scan tab scans; "c" on a highlighted item opens a prompt to
override its category, which both feeds the local classifier
(``classify.py``) an online-learning example *and* sticks for the rest of
this session (``self.organize_overrides``) — re-running ``propose_moves``
after one correction won't necessarily flip that file's prediction back
immediately (a single example rarely outweighs the seeded prior), so the
override is applied on top of every subsequent refresh until the tab is
closed.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from rich.text import Text
from textual import work
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Grid, Vertical
from textual.screen import ModalScreen, Screen
from textual.widgets import (
    Button,
    Footer,
    Header,
    Input,
    Label,
    OptionList,
    SelectionList,
    Sparkline,
    Static,
    TabbedContent,
    TabPane,
)
from textual.widgets.option_list import Option
from textual.widgets.selection_list import Selection

from filecleaner import audit as audit_mod
from filecleaner import classify, scanner
from filecleaner import config as config_mod
from filecleaner import format as fmt
from filecleaner import organize as organize_mod
from filecleaner import profiles as profiles_mod
from filecleaner import quarantine as quarantine_mod
from filecleaner import rules as rules_mod
from filecleaner import volumes as volumes_mod
from filecleaner.models import Candidate, OrganizeMove, QuarantineEntry, Rule, ScanResult

_DIALOG_CSS = """
ConfirmScreen, TextPromptScreen, ThresholdScreen {
    align: center middle;
}
#dialog {
    grid-size: 2;
    grid-gutter: 1 2;
    grid-rows: auto auto;
    padding: 1 2;
    width: 70%;
    max-width: 70;
    height: auto;
    border: thick $background 80%;
    background: $surface;
}
#question {
    column-span: 2;
    content-align: center middle;
    padding: 1 0;
}
#prompt_inputs {
    column-span: 2;
    height: auto;
}
#prompt_input {
    column-span: 2;
}
"""


class ConfirmScreen(ModalScreen[bool]):
    """A yes/no dialog with no default-yes.

    Escape always cancels. Confirming requires deliberately moving focus to
    the "Confirm" button (Tab, or an arrow key) and activating it — Button
    itself binds Enter/Space to "press the focused button", and focus
    starts on "Cancel", so an unmodified Enter press here safely cancels
    rather than confirming.
    """

    CSS = _DIALOG_CSS
    BINDINGS = [Binding("escape", "cancel", "Cancel", show=False)]

    def __init__(self, message: str) -> None:
        super().__init__()
        self.message = message

    def compose(self) -> ComposeResult:
        yield Grid(
            Label(self.message, id="question"),
            Button("Cancel", variant="primary", id="no"),
            Button("Confirm", variant="error", id="yes"),
            id="dialog",
        )

    def on_mount(self) -> None:
        self.query_one("#no", Button).focus()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        self.dismiss(event.button.id == "yes")

    def action_cancel(self) -> None:
        self.dismiss(False)


class TextPromptScreen(ModalScreen[str | None]):
    """A single-line text prompt (e.g. "name this profile"). Escape or
    "Cancel" returns None; "Confirm" returns the (stripped) input text,
    which may be empty — callers validate that themselves."""

    CSS = _DIALOG_CSS
    BINDINGS = [Binding("escape", "cancel", "Cancel", show=False)]

    def __init__(self, message: str, *, initial: str = "") -> None:
        super().__init__()
        self.message = message
        self.initial = initial

    def compose(self) -> ComposeResult:
        yield Grid(
            Label(self.message, id="question"),
            Input(value=self.initial, id="prompt_input"),
            Button("Cancel", variant="primary", id="no"),
            Button("Confirm", variant="success", id="yes"),
            id="dialog",
        )

    def on_mount(self) -> None:
        self.query_one("#prompt_input", Input).focus()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        self._submit(event.button.id == "yes")

    def on_input_submitted(self, event: Input.Submitted) -> None:
        self._submit(True)

    def _submit(self, confirmed: bool) -> None:
        if not confirmed:
            self.dismiss(None)
            return
        self.dismiss(self.query_one("#prompt_input", Input).value.strip())

    def action_cancel(self) -> None:
        self.dismiss(None)


class ThresholdScreen(ModalScreen[tuple[int | None, int | None] | None]):
    """Edit one rule's min_age_days/min_size_bytes override. An empty field
    means "no override for this field" (clears any existing one); Cancel or
    Escape returns None and changes nothing."""

    CSS = _DIALOG_CSS
    BINDINGS = [Binding("escape", "cancel", "Cancel", show=False)]

    def __init__(self, rule: Rule, effective: Rule) -> None:
        super().__init__()
        self.rule = rule
        self.effective = effective

    def compose(self) -> ComposeResult:
        yield Grid(
            Label(f"Thresholds for {self.rule.id}", id="question"),
            Vertical(
                Label("Min age (days), blank = no override:"),
                Input(value=str(self.effective.min_age_days), id="age_input"),
                Label("Min size (bytes), blank = no override:"),
                Input(value=str(self.effective.min_size_bytes), id="size_input"),
                id="prompt_inputs",
            ),
            Button("Cancel", variant="primary", id="no"),
            Button("Save", variant="success", id="yes"),
            id="dialog",
        )

    def on_mount(self) -> None:
        self.query_one("#age_input", Input).focus()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id != "yes":
            self.dismiss(None)
            return
        age_text = self.query_one("#age_input", Input).value.strip()
        size_text = self.query_one("#size_input", Input).value.strip()
        try:
            age = int(age_text) if age_text else None
            size = int(size_text) if size_text else None
        except ValueError:
            self.notify("Enter whole numbers only.", severity="error")
            return
        self.dismiss((age, size))

    def action_cancel(self) -> None:
        self.dismiss(None)


def _candidate_label(cand: Candidate) -> Text:
    risk_tag = {"low": "", "medium": " ⚠", "high": " ⚠⚠"}.get(cand.risk, "")
    kind = "dir " if cand.is_dir else "file"
    return Text(f"{fmt.human_size(cand.size_bytes):>10}  {kind}  [{cand.category}]{risk_tag}  {cand.path}")


def _entry_label(entry: QuarantineEntry) -> Text:
    availability = "" if entry.is_available else "  (unavailable — volume unplugged?)"
    return Text(f"{fmt.human_size(entry.size_bytes):>10}  {fmt.short_timestamp(entry.timestamp)}  {entry.original_path}{availability}")


def _organize_label(move: OrganizeMove, root: Path) -> Text:
    try:
        rel = move.destination.relative_to(root)
    except ValueError:
        rel = move.destination
    return Text(f"{move.path.name}  ->  {rel}  [{move.confidence:.0%}] ({move.reason})")


def _rule_label(rule: Rule, effective: Rule) -> Text:
    risk_tag = {"low": "[low]", "medium": "[medium]", "high": "[high]"}.get(rule.risk, "")
    overridden = " (custom thresholds)" if effective != rule else ""
    return Text(
        f"{rule.category:<12}  {risk_tag:<10}  {rule.id}{overridden}  "
        f"age>={effective.min_age_days}d size>={fmt.human_size(effective.min_size_bytes)}"
    )


class QuarantineScreen(Screen):
    BINDINGS = [
        Binding("escape", "app.pop_screen", "Back"),
        Binding("r", "restore_selected", "Restore selected"),
        Binding("a", "select_all", "Select all"),
        Binding("n", "select_none", "Select none"),
    ]

    def compose(self) -> ComposeResult:
        yield Header()
        yield Static("Loading quarantine…", id="quarantine_help")
        yield SelectionList(id="quarantine_list")
        yield Footer()

    def on_mount(self) -> None:
        self.entry_by_key: dict[str, QuarantineEntry] = {}
        self.refresh_list()

    def refresh_list(self) -> None:
        cfg = config_mod.load_config()
        entries = quarantine_mod.list_entries(cfg)
        selection_list = self.query_one("#quarantine_list", SelectionList)
        selection_list.clear_options()
        self.entry_by_key = {}
        for i, entry in enumerate(entries):
            key = str(i)
            self.entry_by_key[key] = entry
            selection_list.add_option(Selection(_entry_label(entry), key, False))
        total = sum(e.size_bytes for e in entries)
        self.query_one("#quarantine_help", Static).update(
            f"Quarantine: {len(entries)} item(s), {fmt.human_size(total)} — space, then r to restore, escape to go back"
        )

    def action_select_all(self) -> None:
        self.query_one("#quarantine_list", SelectionList).select_all()

    def action_select_none(self) -> None:
        self.query_one("#quarantine_list", SelectionList).deselect_all()

    @work(exclusive=True)
    async def action_restore_selected(self) -> None:
        # See the matching comment on FileCleanerApp.action_quarantine_selected:
        # push_screen_wait needs an active worker, not a bare action method.
        selection_list = self.query_one("#quarantine_list", SelectionList)
        selected = [self.entry_by_key[k] for k in selection_list.selected]
        if not selected:
            self.notify("Nothing selected. Press space to select items first.")
            return
        confirmed = await self.app.push_screen_wait(
            ConfirmScreen(f"Restore {len(selected)} item(s) to their original locations?")
        )
        if not confirmed:
            return
        cfg = config_mod.load_config()
        action = quarantine_mod.restore_entries([e.id for e in selected], cfg)
        message = f"Restored {len(action.entries)} item(s)."
        if action.skipped:
            message += f" {len(action.skipped)} skipped."
        self.notify(message)
        self.refresh_list()


class FileCleanerApp(App[None]):
    """Scan / Rules / Profiles / Stats / Organize tabs, plus a pushed Quarantine screen."""

    TITLE = "File Cleaner"
    CSS = """
    #volume_summary {
        height: auto;
        padding: 1 1;
        border-bottom: solid $accent;
    }
    #status {
        height: auto;
        padding: 0 1;
        color: $text-muted;
    }
    #rules_help, #profiles_help, #stats_summary, #organize_help {
        height: auto;
        padding: 1 1;
        color: $text-muted;
    }
    #stats_sparkline {
        height: 5;
        margin: 1 1;
    }
    """
    BINDINGS = [
        Binding("r", "rescan", "Rescan"),
        Binding("a", "select_all", "Select all"),
        Binding("n", "select_none", "Select none"),
        # Not "enter": SelectionList's own base class (OptionList) already
        # binds Enter to its own internal action and handles it before the
        # key ever bubbles up to the app, so an app-level Enter binding here
        # would silently never fire while the list has focus — exactly
        # where it has focus almost all the time.
        Binding("x", "quarantine_selected", "Quarantine selected"),
        Binding("e", "edit_threshold", "Edit thresholds (Rules tab)"),
        Binding("s", "save_profile", "Save profile (Profiles tab)"),
        Binding("d", "delete_profile", "Delete profile (Profiles tab)"),
        Binding("m", "apply_organize", "Move selected (Organize tab)"),
        Binding("c", "recategorize", "Re-categorize highlighted (Organize tab)"),
        Binding("u", "show_quarantine", "Quarantine/Restore"),
        Binding("q", "quit", "Quit"),
    ]

    def __init__(self, *, root: Path | None = None) -> None:
        super().__init__()
        self.config: dict[str, Any] = config_mod.load_config()
        self.root = root
        self.scan_result: ScanResult | None = None
        self.candidate_by_key: dict[str, Candidate] = {}
        self.rule_by_index: dict[int, Rule] = {}
        self.organize_move_by_index: dict[int, OrganizeMove] = {}
        self.organize_overrides: dict[Path, str] = {}

    def compose(self) -> ComposeResult:
        yield Header()
        with TabbedContent(initial="tab-scan"):
            with TabPane("Scan", id="tab-scan"):
                yield Static(id="volume_summary")
                yield Static(id="status")
                yield SelectionList(id="candidates")
            with TabPane("Rules", id="tab-rules"):
                yield Static(id="rules_help")
                yield SelectionList(id="rules_list")
            with TabPane("Profiles", id="tab-profiles"):
                yield Static(id="profiles_help")
                yield OptionList(id="profiles_list")
            with TabPane("Stats", id="tab-stats"):
                yield Static(id="stats_summary")
                yield Sparkline([], id="stats_sparkline")
            with TabPane("Organize", id="tab-organize"):
                yield Static(id="organize_help")
                yield SelectionList(id="organize_moves")
        yield Footer()

    def on_mount(self) -> None:
        self._refresh_volume_summary()
        self._refresh_rules_list()
        self._refresh_profiles_list()
        self._refresh_stats()
        self._refresh_organize_list()
        self.action_rescan()

    def on_tabbed_content_tab_activated(self, event: TabbedContent.TabActivated) -> None:
        # Data behind Rules/Profiles/Stats/Organize can go stale while another
        # tab was active (a scan just ran, a profile was applied elsewhere,
        # files changed on disk) — refresh on activation rather than trying
        # to invalidate every write site.
        if event.pane.id == "tab-rules":
            self._refresh_rules_list()
        elif event.pane.id == "tab-profiles":
            self._refresh_profiles_list()
        elif event.pane.id == "tab-stats":
            self._refresh_stats()
        elif event.pane.id == "tab-organize":
            self._refresh_organize_list()

    def _active_tab(self) -> str:
        return self.query_one(TabbedContent).active

    # ---------------------------------------------------------------- Scan

    def action_rescan(self) -> None:
        tab = self._active_tab()
        if tab == "tab-organize":
            self._refresh_organize_list()
            return
        if tab != "tab-scan":
            self.notify("Switch to the Scan tab to rescan.")
            return
        self.query_one("#status", Static).update("Scanning…")
        self.query_one("#candidates", SelectionList).clear_options()
        self._scan()

    @work(exclusive=True, thread=True)
    def _scan(self) -> None:
        def progress(message: str, percent: float | None) -> None:
            # message embeds a relative filesystem path — wrap in Text (see
            # module docstring) so it can never be mistaken for markup.
            label = f"[{percent:5.1f}%] {message}" if percent is not None else message
            self.call_from_thread(self.query_one("#status", Static).update, Text(label))

        # No counting pre-pass: it walked the whole tree a second time just to
        # turn the status line into a percentage. The scan reports a running
        # folder count as it goes instead.
        result = scanner.run_scan(self.config, progress=progress, root=self.root)
        audit_mod.log_scan(result)
        self.call_from_thread(self._on_scan_done, result)

    def _on_scan_done(self, result: ScanResult) -> None:
        self.scan_result = result
        self._refresh_volume_summary()
        self._refresh_candidate_list()
        status = f"Done in {result.duration_seconds:.1f}s."
        if result.errors:
            status += f" {len(result.errors)} path(s) skipped due to read errors."
        self.query_one("#status", Static).update(Text(status))

    def _refresh_volume_summary(self) -> None:
        effective_root = (self.root or Path.cwd()).expanduser().resolve()
        if effective_root == Path.home().resolve():
            lines = ["Scanning: home directory + external volumes"]
        else:
            lines = [f"Scanning: {effective_root} (pass a root of `~` for the whole-machine scan)"]
        for vol in volumes_mod.list_volumes():
            lines.append(f"{vol.name}: {fmt.human_size(vol.free_bytes)} free / {fmt.human_size(vol.total_bytes)} ({vol.percent_used:.0f}% used)")
        if self.scan_result is not None:
            lines.append(
                f"Reclaimable: {fmt.human_size(self.scan_result.total_size)} "
                f"across {len(self.scan_result.candidates)} items — space is only freed after you select "
                "items (space) and quarantine them (x)"
            )
        # vol.name is a user-assigned volume label and may contain brackets;
        # wrap in Text so it is never mistaken for markup (see module docstring).
        self.query_one("#volume_summary", Static).update(Text("\n".join(lines)))

    def _refresh_candidate_list(self) -> None:
        selection_list = self.query_one("#candidates", SelectionList)
        selection_list.clear_options()
        self.candidate_by_key = {}
        if self.scan_result is None:
            return
        candidates = sorted(self.scan_result.candidates, key=lambda c: c.size_bytes, reverse=True)
        for i, cand in enumerate(candidates):
            key = str(i)
            self.candidate_by_key[key] = cand
            selection_list.add_option(Selection(_candidate_label(cand), key, False))

    def action_show_quarantine(self) -> None:
        self.push_screen(QuarantineScreen())

    @work(exclusive=True)
    async def action_quarantine_selected(self) -> None:
        # `push_screen_wait` below requires an active Textual worker to
        # await on — without `@work` here, Textual raises `NoActiveWorker`
        # the moment this runs, since the key-binding dispatcher invokes
        # action methods directly rather than as a worker task.
        if self._active_tab() != "tab-scan":
            return
        selection_list = self.query_one("#candidates", SelectionList)
        selected = [self.candidate_by_key[k] for k in selection_list.selected]
        if not selected:
            self.notify("Nothing selected. Press space to select items first.")
            return
        total = sum(c.size_bytes for c in selected)
        confirmed = await self.push_screen_wait(
            ConfirmScreen(
                f"Quarantine {len(selected)} item(s) ({fmt.human_size(total)})?\n"
                f"Restorable for {self.config['retention_days']} days."
            )
        )
        if not confirmed:
            return
        roots = tuple(self.scan_result.scan_roots) if self.scan_result else ()
        action = quarantine_mod.quarantine_candidates(selected, self.config, allowed_roots=roots)
        message = f"Quarantined {len(action.entries)} item(s) ({fmt.human_size(action.total_size)})."
        if action.skipped:
            message += f" {len(action.skipped)} skipped."
        self.notify(message)
        self.action_rescan()

    # --------------------------------------------------------------- Rules

    def _refresh_rules_list(self) -> None:
        self.config = config_mod.load_config()
        selection_list = self.query_one("#rules_list", SelectionList)
        selection_list.clear_options()
        self.rule_by_index = {}
        all_rules = sorted(rules_mod.all_rules(self.config), key=lambda r: (r.category, r.id))
        effective_by_id = {r.id: r for r in rules_mod.apply_param_overrides(list(all_rules), self.config)}
        for i, rule in enumerate(all_rules):
            self.rule_by_index[i] = rule
            enabled = config_mod.is_rule_enabled(self.config, rule.id, rule.enabled_by_default)
            effective = effective_by_id[rule.id]
            selection_list.add_option(Selection(_rule_label(rule, effective), rule.id, enabled))
        self.query_one("#rules_help", Static).update(
            f"{len(all_rules)} rule(s) — space toggles enabled/disabled, e edits thresholds for the highlighted rule"
        )

    def on_selection_list_selection_toggled(self, event: SelectionList.SelectionToggled) -> None:
        if event.selection_list.id != "rules_list":
            return
        rule_id = event.selection.value
        enabled = rule_id in event.selection_list.selected
        self.config.setdefault("rule_overrides", {})[rule_id] = enabled
        config_mod.save_config(self.config)

    def action_edit_threshold(self) -> None:
        if self._active_tab() != "tab-rules":
            return
        selection_list = self.query_one("#rules_list", SelectionList)
        index = selection_list.highlighted
        if index is None or index not in self.rule_by_index:
            self.notify("Highlight a rule first.")
            return
        rule = self.rule_by_index[index]
        effective = rules_mod.apply_param_overrides([rule], self.config)[0]
        self._prompt_threshold(rule, effective)

    @work(exclusive=True)
    async def _prompt_threshold(self, rule: Rule, effective: Rule) -> None:
        result = await self.push_screen_wait(ThresholdScreen(rule, effective))
        if result is None:
            return
        age, size = result
        if age is None and size is None:
            config_mod.clear_rule_param_override(self.config, rule.id)
        else:
            config_mod.set_rule_param_override(self.config, rule.id, min_age_days=age, min_size_bytes=size)
        config_mod.save_config(self.config)
        self._refresh_rules_list()
        self.notify(f"Updated thresholds for {rule.id}.")

    # ------------------------------------------------------------ Profiles

    def _refresh_profiles_list(self) -> None:
        self.config = config_mod.load_config()
        option_list = self.query_one("#profiles_list", OptionList)
        option_list.clear_options()
        active = self.config.get("active_profile") or None
        names = profiles_mod.list_profiles()
        for name in names:
            marker = " (active)" if name == active else ""
            option_list.add_option(Option(f"{name}{marker}", id=name))
        self.query_one("#profiles_help", Static).update(
            f"{len(names)} saved profile(s) — enter applies the highlighted profile, "
            "s saves the current config as a new profile, d deletes the highlighted one"
        )

    def on_option_list_option_selected(self, event: OptionList.OptionSelected) -> None:
        if event.option_list.id != "profiles_list" or event.option.id is None:
            return
        name = event.option.id
        try:
            merged = profiles_mod.apply_profile(self.config, name)
        except (profiles_mod.ProfileError, config_mod.ConfigError) as exc:
            self.notify(str(exc), severity="error")
            return
        merged["active_profile"] = name
        config_mod.save_config(merged)
        self.config = merged
        self._refresh_profiles_list()
        self._refresh_rules_list()
        self.notify(f"Applied profile {name!r}. Rescan to see it take effect.")

    def action_save_profile(self) -> None:
        if self._active_tab() != "tab-profiles":
            return
        self._prompt_save_profile()

    @work(exclusive=True)
    async def _prompt_save_profile(self) -> None:
        name = await self.push_screen_wait(TextPromptScreen("Save current config as profile named:"))
        if not name:
            return
        try:
            profiles_mod.save_profile(name, self.config)
        except profiles_mod.ProfileError as exc:
            self.notify(str(exc), severity="error")
            return
        self._refresh_profiles_list()
        self.notify(f"Saved profile {name!r}.")

    def action_delete_profile(self) -> None:
        if self._active_tab() != "tab-profiles":
            return
        option_list = self.query_one("#profiles_list", OptionList)
        index = option_list.highlighted
        if index is None:
            self.notify("Highlight a profile first.")
            return
        option = option_list.get_option_at_index(index)
        if option.id is None:
            return
        self._confirm_delete_profile(option.id)

    @work(exclusive=True)
    async def _confirm_delete_profile(self, name: str) -> None:
        confirmed = await self.push_screen_wait(ConfirmScreen(f"Delete profile {name!r}?"))
        if not confirmed:
            return
        profiles_mod.delete_profile(name)
        if self.config.get("active_profile") == name:
            self.config["active_profile"] = ""
            config_mod.save_config(self.config)
        self._refresh_profiles_list()
        self.notify(f"Deleted profile {name!r}.")

    # --------------------------------------------------------------- Stats

    def _refresh_stats(self) -> None:
        cfg = config_mod.load_config()
        item_count, total_bytes = quarantine_mod.overall_summary(cfg)
        by_category = quarantine_mod.history_by_category(cfg)
        by_day = quarantine_mod.history_by_day(cfg, days=30)
        recent = audit_mod.read_audit_log(limit=10)

        lines = [
            f"Currently in quarantine: {item_count} item(s), {fmt.human_size(total_bytes)}",
            "",
            "All-time by category:",
        ]
        for row in by_category[:8]:
            lines.append(f"  {row['category']:<12} {row['count']:>5} item(s)  {fmt.human_size(row['size_bytes'])}")
        if not by_category:
            lines.append("  (nothing quarantined yet)")
        lines.append("")
        lines.append("Recent activity:")
        for entry in reversed(recent):
            action = entry.get("action", "?")
            ts = fmt.short_timestamp(entry.get("timestamp", ""))
            lines.append(f"  {ts}  {action}")
        if not recent:
            lines.append("  (nothing logged yet)")

        self.query_one("#stats_summary", Static).update("\n".join(lines))
        self.query_one("#stats_sparkline", Sparkline).data = [row["size_bytes"] for row in by_day] or [0]

    # ------------------------------------------------------------ Organize

    def _refresh_organize_list(self) -> None:
        self.config = config_mod.load_config()
        effective_root = (self.root or Path.cwd()).expanduser().resolve()
        selection_list = self.query_one("#organize_moves", SelectionList)
        selection_list.clear_options()
        self.organize_move_by_index = {}

        try:
            moves = organize_mod.propose_moves(effective_root, self.config)
        except organize_mod.OrganizeError as exc:
            self.notify(str(exc), severity="error")
            moves = []

        # Session-local manual corrections (see module docstring) always win
        # over whatever the classifier currently predicts for that file.
        for move in moves:
            override = self.organize_overrides.get(move.path)
            if override is not None and move.category != override:
                move.category = override
                move.destination = effective_root / override / move.path.name
                move.confidence = 1.0
                move.reason = "manual"

        for i, move in enumerate(sorted(moves, key=lambda m: str(m.path))):
            self.organize_move_by_index[i] = move
            selection_list.add_option(Selection(_organize_label(move, effective_root), str(i), False))

        self.query_one("#organize_help", Static).update(
            f"{len(moves)} file(s) proposed for {effective_root} — space selects, m moves the selected "
            "item(s), c re-categorizes the highlighted item, r refreshes the plan"
        )

    @work(exclusive=True)
    async def action_apply_organize(self) -> None:
        if self._active_tab() != "tab-organize":
            return
        selection_list = self.query_one("#organize_moves", SelectionList)
        selected = [self.organize_move_by_index[int(k)] for k in selection_list.selected]
        if not selected:
            self.notify("Nothing selected. Press space to select items first.")
            return
        confirmed = await self.push_screen_wait(ConfirmScreen(f"Move {len(selected)} file(s) into subfolders?"))
        if not confirmed:
            return
        result = organize_mod.apply_moves(selected, self.config)
        message = f"Moved {len(result.entries)} item(s)."
        if result.skipped:
            message += f" {len(result.skipped)} skipped."
        self.notify(message)
        self._refresh_organize_list()

    def action_recategorize(self) -> None:
        if self._active_tab() != "tab-organize":
            return
        selection_list = self.query_one("#organize_moves", SelectionList)
        index = selection_list.highlighted
        if index is None or index not in self.organize_move_by_index:
            self.notify("Highlight a file first.")
            return
        self._prompt_recategorize(self.organize_move_by_index[index])

    @work(exclusive=True)
    async def _prompt_recategorize(self, move: OrganizeMove) -> None:
        new_category = await self.push_screen_wait(
            TextPromptScreen(f"New category for {move.path.name} (currently {move.category}):", initial=move.category)
        )
        if not new_category:
            return
        clf = classify.load()
        clf.update(move.path, new_category)
        classify.save(clf)
        self.organize_overrides[move.path] = new_category
        self._refresh_organize_list()
        self.notify(f"Learned: {move.path.name} -> {new_category}")

    # ------------------------------------------------------------- Shared

    def action_select_all(self) -> None:
        tab = self._active_tab()
        if tab == "tab-scan":
            self.query_one("#candidates", SelectionList).select_all()
        elif tab == "tab-rules":
            self.query_one("#rules_list", SelectionList).select_all()
        elif tab == "tab-organize":
            self.query_one("#organize_moves", SelectionList).select_all()

    def action_select_none(self) -> None:
        tab = self._active_tab()
        if tab == "tab-scan":
            self.query_one("#candidates", SelectionList).deselect_all()
        elif tab == "tab-rules":
            self.query_one("#rules_list", SelectionList).deselect_all()
        elif tab == "tab-organize":
            self.query_one("#organize_moves", SelectionList).deselect_all()


def run_tui(*, root: Path | None = None) -> None:
    FileCleanerApp(root=root).run()
