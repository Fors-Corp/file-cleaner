"""Smoke tests for the Textual app: launches it headless, drives it with a
Pilot, and checks the screens/labels it renders. These also exercise the
bracket-preservation fix (see tui.py's module docstring) end to end through
the real SelectionList widget, not just the isolated Selection() probe.
"""

from __future__ import annotations

import pytest
from textual.widgets import OptionList, SelectionList, TabbedContent

from filecleaner import config as config_mod
from filecleaner import profiles as profiles_mod
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


async def test_rules_tab_toggle_persists_to_config(sandbox_home):
    app = tui_mod.FileCleanerApp()
    async with app.run_test() as pilot:
        await pilot.pause()
        while app.scan_result is None:
            await pilot.pause()

        app.query_one(TabbedContent).active = "tab-rules"
        await pilot.pause()

        rules_list = app.query_one("#rules_list", SelectionList)
        # system_caches is enabled by default — find its index rather than
        # assuming position, since rules are sorted by (category, id).
        index = next(i for i, r in app.rule_by_index.items() if r.id == "system_caches")
        assert "system_caches" in rules_list.selected

        rules_list.focus()
        await pilot.pause()
        # The first "down" only moves the cursor from unhighlighted onto
        # option 0 — it takes index+1 presses to land on option `index`.
        for _ in range(index + 1):
            await pilot.press("down")
        await pilot.press("space")
        await pilot.pause()

        cfg = config_mod.load_config()
        assert cfg["rule_overrides"]["system_caches"] is False


async def test_rules_tab_edit_threshold_dialog(sandbox_home):
    app = tui_mod.FileCleanerApp()
    async with app.run_test() as pilot:
        await pilot.pause()
        while app.scan_result is None:
            await pilot.pause()

        app.query_one(TabbedContent).active = "tab-rules"
        await pilot.pause()
        rules_list = app.query_one("#rules_list", SelectionList)
        rules_list.focus()
        rules_list.highlighted = next(i for i, r in app.rule_by_index.items() if r.id == "system_caches")
        await pilot.pause()

        await pilot.press("e")
        await pilot.pause()
        assert isinstance(app.screen, tui_mod.ThresholdScreen)

        age_input = app.screen.query_one("#age_input")
        age_input.value = "99"
        await pilot.press("tab", "tab", "enter")  # age_input -> size_input -> Cancel; enter presses focused button
        for _ in range(20):
            await pilot.pause()
            if not isinstance(app.screen, tui_mod.ThresholdScreen):
                break

        # Cancel was pressed (default focus order), so nothing should be saved.
        cfg = config_mod.load_config()
        assert cfg.get("rule_param_overrides", {}).get("system_caches") is None


async def test_rules_tab_edit_threshold_dialog_save_path(sandbox_home):
    app = tui_mod.FileCleanerApp()
    async with app.run_test() as pilot:
        await pilot.pause()
        while app.scan_result is None:
            await pilot.pause()

        app.query_one(TabbedContent).active = "tab-rules"
        await pilot.pause()
        rules_list = app.query_one("#rules_list", SelectionList)
        rules_list.highlighted = next(i for i, r in app.rule_by_index.items() if r.id == "system_caches")
        await pilot.pause()

        await pilot.press("e")
        await pilot.pause()
        assert isinstance(app.screen, tui_mod.ThresholdScreen)

        app.screen.query_one("#age_input").value = "99"
        # age_input -> size_input -> Cancel -> Save; enter presses the focused button.
        await pilot.press("tab", "tab", "tab", "enter")
        for _ in range(20):
            await pilot.pause()
            if not isinstance(app.screen, tui_mod.ThresholdScreen):
                break

        cfg = config_mod.load_config()
        assert cfg["rule_param_overrides"]["system_caches"]["min_age_days"] == 99


async def test_profiles_tab_save_and_apply(sandbox_home):
    app = tui_mod.FileCleanerApp()
    async with app.run_test() as pilot:
        await pilot.pause()
        while app.scan_result is None:
            await pilot.pause()

        app.query_one(TabbedContent).active = "tab-profiles"
        await pilot.pause()

        await pilot.press("s")
        await pilot.pause()
        assert isinstance(app.screen, tui_mod.TextPromptScreen)
        app.screen.query_one("#prompt_input").value = "myprofile"
        await pilot.press("enter")  # Input.Submitted -> confirms directly
        for _ in range(20):
            await pilot.pause()
            if not isinstance(app.screen, tui_mod.TextPromptScreen):
                break

        assert profiles_mod.list_profiles() == ["myprofile"]

        options = app.query_one("#profiles_list", OptionList)
        assert options.option_count == 1


async def test_stats_tab_reflects_quarantine_history(sandbox_home, cache_item):
    app = tui_mod.FileCleanerApp()
    async with app.run_test() as pilot:
        await pilot.pause()
        while app.scan_result is None:
            await pilot.pause()

        candidate = app.scan_result.candidates[0]
        quarantine_mod.quarantine_candidates([candidate], app.config)

        app.query_one(TabbedContent).active = "tab-stats"
        await pilot.pause()

        summary = app.query_one("#stats_summary").content
        text = summary.plain if hasattr(summary, "plain") else str(summary)
        assert "Caches" in text
