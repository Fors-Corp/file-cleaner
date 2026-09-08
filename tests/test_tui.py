"""Smoke tests for the Textual app: launches it headless, drives it with a
Pilot, and checks the screens/labels it renders. These also exercise the
bracket-preservation fix (see tui.py's module docstring) end to end through
the real SelectionList widget, not just the isolated Selection() probe.
"""

from __future__ import annotations

import pytest
from textual.widgets import SelectionList

from filecleaner import quarantine as quarantine_mod
from filecleaner import tui as tui_mod


@pytest.fixture
def cache_item(sandbox_home, age_path):
    cache_dir = sandbox_home / "Library" / "Caches" / "App [Beta]"
    cache_dir.mkdir(parents=True)
    data = cache_dir / "data.bin"
    data.write_bytes(b"x" * 1024)
    age_path(cache_dir, days=10)
    age_path(data, days=10)
    return cache_dir


async def test_app_launches_and_lists_candidate(cache_item, sandbox_home):
    app = tui_mod.FileCleanerApp()
    async with app.run_test() as pilot:
        await pilot.pause()
        while app.scan_result is None:
            await pilot.pause()
        selection_list = app.query_one("#candidates", SelectionList)
        assert selection_list.option_count == 1


async def test_bracketed_category_survives_in_selection_label(cache_item, sandbox_home):
    """The real bug this guards against: Textual's markup parser silently
    drops a bracketed run that looks like a style tag (e.g. a bare word in
    brackets). Category names like "Caches" rendered as "[Caches]" must
    stay visible verbatim, not vanish."""
    app = tui_mod.FileCleanerApp()
    async with app.run_test() as pilot:
        await pilot.pause()
        while app.scan_result is None:
            await pilot.pause()
        selection_list = app.query_one("#candidates", SelectionList)
        option = selection_list.get_option_at_index(0)
        rendered = option.prompt.plain
        assert "[Caches]" in rendered
        assert "App [Beta]" in rendered  # the folder's own bracketed name too


async def test_select_and_quarantine_via_confirm_dialog(cache_item, sandbox_home):
    app = tui_mod.FileCleanerApp()
    async with app.run_test() as pilot:
        await pilot.pause()
        while app.scan_result is None:
            await pilot.pause()

        selection_list = app.query_one("#candidates", SelectionList)
        selection_list.focus()
        await pilot.press("down")  # move the highlight onto the (only) option
        await pilot.press("space")  # toggle it selected
        await pilot.press("x")  # quarantine_selected -> opens ConfirmScreen
        await pilot.pause()

        assert isinstance(app.screen, tui_mod.ConfirmScreen)
        await pilot.press("tab")  # move focus from "Cancel" to "Confirm"
        await pilot.press("enter")  # Button's own binding: press the focused button
        for _ in range(50):
            await pilot.pause()
            if not cache_item.exists():
                break

        assert not cache_item.exists()
        cfg = app.config
        entries = quarantine_mod.list_entries(cfg)
        assert len(entries) == 1


async def test_confirm_dialog_enter_safely_cancels_by_default(cache_item, sandbox_home):
    """Focus starts on "Cancel", and Button's own Enter binding presses
    whichever button is focused — so an unmodified Enter here must cancel,
    never confirm. This is what keeps ConfirmScreen free of a default-yes."""
    app = tui_mod.FileCleanerApp()
    async with app.run_test() as pilot:
        await pilot.pause()
        while app.scan_result is None:
            await pilot.pause()

        selection_list = app.query_one("#candidates", SelectionList)
        selection_list.focus()
        await pilot.press("down")
        await pilot.press("space")
        await pilot.press("x")
        await pilot.pause()
        assert isinstance(app.screen, tui_mod.ConfirmScreen)

        await pilot.press("enter")
        await pilot.pause()

        assert cache_item.exists()


async def test_confirm_dialog_escape_cancels(cache_item, sandbox_home):
    app = tui_mod.FileCleanerApp()
    async with app.run_test() as pilot:
        await pilot.pause()
        while app.scan_result is None:
            await pilot.pause()

        selection_list = app.query_one("#candidates", SelectionList)
        selection_list.focus()
        await pilot.press("down")
        await pilot.press("space")
        await pilot.press("x")
        await pilot.pause()
        assert isinstance(app.screen, tui_mod.ConfirmScreen)

        await pilot.press("escape")  # ConfirmScreen's own binding: cancel
        await pilot.pause()

        assert cache_item.exists()


async def test_quarantine_screen_lists_and_restores(cache_item, sandbox_home):
    app = tui_mod.FileCleanerApp()
    async with app.run_test() as pilot:
        await pilot.pause()
        while app.scan_result is None:
            await pilot.pause()

        # Quarantine it directly (skip the UI flow, already covered above).
        candidate = app.scan_result.candidates[0]
        quarantine_mod.quarantine_candidates([candidate], app.config)

        app.action_show_quarantine()
        await pilot.pause()
        assert isinstance(app.screen, tui_mod.QuarantineScreen)

        q_list = app.screen.query_one("#quarantine_list", SelectionList)
        assert q_list.option_count == 1
        label = q_list.get_option_at_index(0).prompt.plain
        assert "App [Beta]" in label

        q_list.focus()
        await pilot.press("down")
        await pilot.press("space")
        await pilot.press("r")  # action_restore_selected -> opens its own ConfirmScreen
        await pilot.pause()
        assert isinstance(app.screen, tui_mod.ConfirmScreen)
        await pilot.press("tab")
        await pilot.press("enter")
        for _ in range(50):
            await pilot.pause()
            if cache_item.exists():
                break

        assert cache_item.exists()
