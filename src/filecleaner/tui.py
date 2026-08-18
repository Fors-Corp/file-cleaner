"""Interactive terminal UI: an ncdu-style browser over cleanup candidates.

Nothing is quarantined without an explicit selection plus a confirmation
dialog — there is no "select all and go" default.
"""

from __future__ import annotations

from textual.app import App, ComposeResult
from textual.containers import Grid
from textual.screen import ModalScreen, Screen
from textual.widgets import Button, Footer, Header, Label, SelectionList, Static
from textual.widgets.selection_list import Selection

from filecleaner import config as config_mod
from filecleaner import format as fmt
from filecleaner import quarantine as quarantine_mod
from filecleaner import scanner
from filecleaner import volumes as volumes_mod

_DIALOG_CSS = """
ConfirmScreen {
    align: center middle;
}
#dialog {
    grid-size: 2;
    grid-gutter: 1 2;
    grid-rows: auto auto;
    padding: 1 2;
    width: 60;
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
    CSS = _DIALOG_CSS

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

    def on_button_pressed(self, event: Button.Pressed) -> None:
        self.dismiss(event.button.id == "yes")


class QuarantineScreen(Screen):
    BINDINGS = [
        ("escape", "app.pop_screen", "Back"),
        ("r", "restore_selected", "Restore selected"),
    ]

    def compose(self) -> ComposeResult:
        yield Header()
        yield Static("Quarantine — select items and press r to restore, escape to go back", id="quarantine_help")
        yield SelectionList(id="quarantine_list")
        yield Footer()

    def on_mount(self) -> None:
        self.entry_by_key: dict[str, object] = {}
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
            label = f"{fmt.human_size(entry.size_bytes):>10}  {entry.timestamp[:19]}  {entry.original_path}"
            selection_list.add_option(Selection(label, key, False))
        total = sum(e.size_bytes for e in entries)
        self.query_one("#quarantine_help", Static).update(
            f"Quarantine: {len(entries)} items, {fmt.human_size(total)} — select items, "
            "press r to restore, escape to go back"
        )

    async def action_restore_selected(self) -> None:
        selection_list = self.query_one("#quarantine_list", SelectionList)
        selected = [self.entry_by_key[k] for k in selection_list.selected]
        if not selected:
            self.notify("Nothing selected.")
            return
        cfg = config_mod.load_config()
        restored = quarantine_mod.restore_entries([e.id for e in selected], cfg)
        self.notify(f"Restored {len(restored)} items.")
        self.refresh_list()


class FileCleanerApp(App):
    TITLE = "File Cleaner"
    CSS = """
    #volume_summary {
        height: auto;
        padding: 1 1;
        border-bottom: solid $accent;
    }
    """
    BINDINGS = [
        ("r", "rescan", "Rescan"),
        ("a", "select_all", "Select all"),
        ("n", "select_none", "Select none"),
        ("enter", "quarantine_selected", "Quarantine selected"),
        ("u", "show_quarantine", "Quarantine/Restore"),
        ("q", "quit", "Quit"),
    ]

    def __init__(self) -> None:
        super().__init__()
        self.config = config_mod.load_config()
        self.scan_result = None
        self.candidate_by_key: dict[str, object] = {}

    def compose(self) -> ComposeResult:
        yield Header()
        yield Static(id="volume_summary")
        yield SelectionList(id="candidates")
        yield Footer()

    def on_mount(self) -> None:
        self.action_rescan()

    def action_rescan(self) -> None:
        self.query_one("#volume_summary", Static).update("Scanning…")
        self.scan_result = scanner.run_scan(self.config)
        self._refresh_volume_summary()
        self._refresh_candidate_list()

    def _refresh_volume_summary(self) -> None:
        lines = []
        for vol in volumes_mod.list_volumes():
            pct = (vol.used_bytes / vol.total_bytes * 100) if vol.total_bytes else 0
            lines.append(f"{vol.name}: {fmt.human_size(vol.free_bytes)} free / {fmt.human_size(vol.total_bytes)} ({pct:.0f}% used)")
        if self.scan_result is not None:
            lines.append(
                f"Reclaimable: {fmt.human_size(self.scan_result.total_size)} "
                f"across {len(self.scan_result.candidates)} items — space is only freed after you select "
                "items and confirm (enter)"
            )
        self.query_one("#volume_summary", Static).update("\n".join(lines))

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
            label = f"{fmt.human_size(cand.size_bytes):>10}  [{cand.category}]  {cand.path}"
            selection_list.add_option(Selection(label, key, False))

    def action_select_all(self) -> None:
        self.query_one("#candidates", SelectionList).select_all()

    def action_select_none(self) -> None:
        self.query_one("#candidates", SelectionList).deselect_all()

    def action_show_quarantine(self) -> None:
        self.push_screen(QuarantineScreen())

    async def action_quarantine_selected(self) -> None:
        selection_list = self.query_one("#candidates", SelectionList)
        selected = [self.candidate_by_key[k] for k in selection_list.selected]
        if not selected:
            self.notify("Nothing selected. Use space to select items first.")
            return
        total = sum(c.size_bytes for c in selected)
        confirmed = await self.push_screen_wait(
            ConfirmScreen(
                f"Quarantine {len(selected)} items ({fmt.human_size(total)})?\n"
                f"Restorable for {self.config['retention_days']} days."
            )
        )
        if not confirmed:
            return
        entries = quarantine_mod.quarantine_candidates(selected, self.config)
        freed = sum(e.size_bytes for e in entries)
        self.notify(f"Quarantined {len(entries)} items ({fmt.human_size(freed)}).")
        self.action_rescan()


def run_tui() -> None:
    FileCleanerApp().run()
