"""Interactive terminal browser: an ncdu-style view over cleanup candidates.

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
"""

from __future__ import annotations

from typing import Any

from rich.text import Text
from textual import work
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Grid
from textual.screen import ModalScreen, Screen
from textual.widgets import Button, Footer, Header, Label, SelectionList, Static
from textual.widgets.selection_list import Selection

from filecleaner import config as config_mod
from filecleaner import format as fmt
from filecleaner import quarantine as quarantine_mod
from filecleaner import scanner
from filecleaner import volumes as volumes_mod
from filecleaner.models import Candidate, QuarantineEntry, ScanResult

_DIALOG_CSS = """
ConfirmScreen {
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


def _candidate_label(cand: Candidate) -> Text:
    risk_tag = {"low": "", "medium": " ⚠", "high": " ⚠⚠"}.get(cand.risk, "")
    kind = "dir " if cand.is_dir else "file"
    return Text(f"{fmt.human_size(cand.size_bytes):>10}  {kind}  [{cand.category}]{risk_tag}  {cand.path}")


def _entry_label(entry: QuarantineEntry) -> Text:
    availability = "" if entry.is_available else "  (unavailable — volume unplugged?)"
    return Text(f"{fmt.human_size(entry.size_bytes):>10}  {fmt.short_timestamp(entry.timestamp)}  {entry.original_path}{availability}")


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
    """The main screen: scan, review, select, quarantine."""

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
        Binding("u", "show_quarantine", "Quarantine/Restore"),
        Binding("q", "quit", "Quit"),
    ]

    def __init__(self) -> None:
        super().__init__()
        self.config: dict[str, Any] = config_mod.load_config()
        self.scan_result: ScanResult | None = None
        self.candidate_by_key: dict[str, Candidate] = {}

    def compose(self) -> ComposeResult:
        yield Header()
        yield Static(id="volume_summary")
        yield Static(id="status")
        yield SelectionList(id="candidates")
        yield Footer()

    def on_mount(self) -> None:
        self._refresh_volume_summary()
        self.action_rescan()

    def action_rescan(self) -> None:
        self.query_one("#status", Static).update("Scanning…")
        self.query_one("#candidates", SelectionList).clear_options()
        self._scan()

    @work(exclusive=True, thread=True)
    def _scan(self) -> None:
        def progress(message: str) -> None:
            # message embeds a relative filesystem path — wrap in Text (see
            # module docstring) so it can never be mistaken for markup.
            self.call_from_thread(self.query_one("#status", Static).update, Text(message))

        result = scanner.run_scan(self.config, progress=progress)
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
        lines = []
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

    def action_select_all(self) -> None:
        self.query_one("#candidates", SelectionList).select_all()

    def action_select_none(self) -> None:
        self.query_one("#candidates", SelectionList).deselect_all()

    def action_show_quarantine(self) -> None:
        self.push_screen(QuarantineScreen())

    @work(exclusive=True)
    async def action_quarantine_selected(self) -> None:
        # `push_screen_wait` below requires an active Textual worker to
        # await on — without `@work` here, Textual raises `NoActiveWorker`
        # the moment this runs, since the key-binding dispatcher invokes
        # action methods directly rather than as a worker task.
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


def run_tui() -> None:
    FileCleanerApp().run()
