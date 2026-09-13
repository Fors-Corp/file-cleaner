"""End-to-end CLI tests via Typer's CliRunner, exercising the real command
wiring (argument parsing, --json output, exit codes, confirmation prompts)
against a sandboxed home/config, never the developer's real machine.
"""

from __future__ import annotations

import json
from datetime import UTC

import pytest
from typer.testing import CliRunner

from filecleaner import cli as cli_mod

runner = CliRunner()


@pytest.fixture
def cache_item(sandbox_home, age_path):
    cache_dir = sandbox_home / "Library" / "Caches" / "SomeApp"
    cache_dir.mkdir(parents=True)
    data = cache_dir / "data.bin"
    data.write_bytes(b"x" * 2048)
    age_path(cache_dir, days=10)
    age_path(data, days=10)
    return cache_dir


def _invoke(*args):
    return runner.invoke(cli_mod.app, list(args))


def test_version_flag(sandbox_home):
    result = _invoke("--version")
    assert result.exit_code == 0
    assert "filecleaner" in result.stdout


def test_no_args_shows_help(sandbox_home):
    result = _invoke()
    assert result.exit_code == 0
    assert "Usage" in result.stdout


def test_scan_json_reports_candidate(cache_item, sandbox_home):
    result = _invoke("scan", "--json")
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["candidate_count"] == 1
    assert payload["candidates"][0]["path"] == str(cache_item)


def test_scan_table_output(cache_item, sandbox_home):
    result = _invoke("scan")
    assert result.exit_code == 0
    assert "Caches" in result.stdout
    assert "Total reclaimable" in result.stdout


def test_scan_unknown_rule_exits_nonzero(sandbox_home):
    # CliRunner surfaces an uncaught CliError as result.exception rather
    # than printed output — cli_mod.CliError is only rendered to the
    # terminal by the real `_entrypoint()` wrapper, exercised separately.
    result = _invoke("scan", "--rules", "not_a_real_rule")
    assert result.exit_code != 0
    assert isinstance(result.exception, cli_mod.CliError)
    assert "unknown rule" in str(result.exception).lower()


def test_clean_dry_run_does_not_move_anything(cache_item, sandbox_home):
    result = _invoke("clean")
    assert result.exit_code == 0
    assert cache_item.exists()
    assert "Dry run" in result.stdout


def test_clean_apply_yes_quarantines_and_restore_brings_it_back(cache_item, sandbox_home):
    result = _invoke("clean", "--apply", "--yes")
    assert result.exit_code == 0
    assert not cache_item.exists()
    assert "Quarantined" in result.stdout

    restored = _invoke("restore", "--yes")
    assert restored.exit_code == 0
    assert cache_item.exists()


def test_clean_apply_without_yes_requires_tty_confirmation(cache_item, sandbox_home):
    # CliRunner's stdin is not a tty, so --apply without --yes must refuse
    # rather than silently defaulting to yes or no.
    result = _invoke("clean", "--apply")
    assert result.exit_code != 0
    assert cache_item.exists()


def test_clean_save_plan_then_apply(cache_item, sandbox_home, tmp_path):
    plan_file = tmp_path / "plan.json"
    result = _invoke("clean", "--save-plan", str(plan_file))
    assert result.exit_code == 0
    assert plan_file.exists()
    assert cache_item.exists()  # save-plan never moves anything

    applied = _invoke("apply", str(plan_file), "--yes")
    assert applied.exit_code == 0
    assert not cache_item.exists()


def test_apply_skips_items_that_changed_since_plan(cache_item, sandbox_home, tmp_path):
    plan_file = tmp_path / "plan.json"
    _invoke("clean", "--save-plan", str(plan_file))
    # Mutate the file after the plan was written.
    (cache_item / "data.bin").write_bytes(b"changed contents, different size!")

    applied = _invoke("apply", str(plan_file), "--yes", "--json")
    assert applied.exit_code == 0
    payload = json.loads(applied.stdout)
    assert payload["count"] == 0
    assert any("modified" in s["reason"] for s in payload["skipped"])
    assert cache_item.exists()


def test_apply_missing_plan_file_errors_cleanly(sandbox_home, tmp_path):
    result = _invoke("apply", str(tmp_path / "nope.json"))
    assert result.exit_code == 1
    assert isinstance(result.exception, cli_mod.CliError)
    assert "cannot read" in str(result.exception).lower()


def test_quarantine_list_and_sessions(cache_item, sandbox_home):
    _invoke("clean", "--apply", "--yes")
    listed = _invoke("quarantine", "list", "--json")
    payload = json.loads(listed.stdout)
    assert payload["entries"][0]["category"] == "Caches"

    sessions = _invoke("quarantine", "sessions", "--json")
    session_payload = json.loads(sessions.stdout)
    assert len(session_payload["sessions"]) == 1


def test_quarantine_purge_without_yes_refuses_non_interactively(cache_item, sandbox_home):
    """`quarantine purge` is the one irreversible command: run without
    --yes and with no real terminal to type a confirmation into (exactly
    the situation a script or a forgotten flag produces), it must refuse
    outright rather than silently defaulting to a "no" (data survives, but
    so does the ambiguity of what actually happened) or, worse, a "yes"."""
    _invoke("clean", "--apply", "--yes")
    result = runner.invoke(cli_mod.app, ["quarantine", "purge", "--all"])
    assert result.exit_code != 0
    assert isinstance(result.exception, cli_mod.CliError)
    assert "--yes" in str(result.exception)
    entries_after = json.loads(_invoke("quarantine", "list", "--json").stdout)
    assert len(entries_after["entries"]) == 1


def test_quarantine_purge_all_yes_deletes_permanently(cache_item, sandbox_home):
    _invoke("clean", "--apply", "--yes")
    result = _invoke("quarantine", "purge", "--all", "--yes")
    assert result.exit_code == 0
    assert "Permanently deleted" in result.stdout
    entries_after = json.loads(_invoke("quarantine", "list", "--json").stdout)
    assert entries_after["entries"] == []


def test_doctor_json(sandbox_home):
    result = _invoke("doctor", "--json")
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert "version" in payload
    assert "rules_total" in payload


def test_doctor_reports_invalid_config(sandbox_home):
    from filecleaner import config as config_mod

    config_mod.ensure_dirs()
    config_mod.CONFIG_FILE.write_text("not [valid toml")
    result = _invoke("doctor")
    assert result.exit_code == 1


def test_config_show_lists_rules(sandbox_home):
    result = _invoke("config", "show")
    assert result.exit_code == 0
    assert "system_caches" in result.stdout


def test_config_enable_disable_round_trip(sandbox_home):
    result = _invoke("config", "enable", "old_downloads")
    assert result.exit_code == 0
    shown = json.loads(_invoke("config", "show", "--json").stdout)
    rule = next(r for r in shown["rules"] if r["id"] == "old_downloads")
    assert rule["enabled"] is True

    _invoke("config", "disable", "old_downloads")
    shown_after = json.loads(_invoke("config", "show", "--json").stdout)
    rule_after = next(r for r in shown_after["rules"] if r["id"] == "old_downloads")
    assert rule_after["enabled"] is False


def test_config_enable_unknown_rule_errors(sandbox_home):
    result = _invoke("config", "enable", "not_a_rule")
    assert result.exit_code == 1


def test_config_keep_and_unkeep(sandbox_home, tmp_path):
    target = str(tmp_path / "important")
    _invoke("config", "keep", target)
    cfg = json.loads(_invoke("config", "show", "--json").stdout)["config"]
    assert target in cfg["protected_paths"]

    _invoke("config", "unkeep", target)
    cfg_after = json.loads(_invoke("config", "show", "--json").stdout)["config"]
    assert target not in cfg_after["protected_paths"]


def test_config_set_and_get(sandbox_home):
    result = _invoke("config", "set", "retention_days", "7")
    assert result.exit_code == 0
    cfg = json.loads(_invoke("config", "show", "--json").stdout)["config"]
    assert cfg["retention_days"] == 7


def test_config_set_invalid_value_errors(sandbox_home):
    result = _invoke("config", "set", "retention_days", "not-a-number")
    assert result.exit_code == 1


def test_config_threshold_round_trip(sandbox_home):
    result = _invoke("config", "threshold", "system_caches", "--min-age-days", "14")
    assert result.exit_code == 0
    cfg = json.loads(_invoke("config", "show", "--json").stdout)["config"]
    assert cfg["rule_param_overrides"]["system_caches"] == {"min_age_days": 14}

    _invoke("config", "clear-threshold", "system_caches")
    cfg_after = json.loads(_invoke("config", "show", "--json").stdout)["config"]
    assert "system_caches" not in cfg_after["rule_param_overrides"]


def test_config_threshold_unknown_rule_errors(sandbox_home):
    result = _invoke("config", "threshold", "not_a_rule", "--min-age-days", "1")
    assert result.exit_code == 1


def test_config_threshold_requires_a_field(sandbox_home):
    result = _invoke("config", "threshold", "system_caches")
    assert result.exit_code == 1


def test_profile_save_list_apply_delete_round_trip(sandbox_home):
    _invoke("config", "set", "retention_days", "7")
    assert _invoke("profile", "save", "quick").exit_code == 0
    listed = json.loads(_invoke("profile", "list", "--json").stdout)
    assert listed["profiles"] == ["quick"]

    _invoke("config", "set", "retention_days", "30")
    assert _invoke("profile", "apply", "quick").exit_code == 0
    cfg = json.loads(_invoke("config", "show", "--json").stdout)["config"]
    assert cfg["retention_days"] == 7
    assert cfg["active_profile"] == "quick"

    assert _invoke("profile", "delete", "quick").exit_code == 0
    listed_after = json.loads(_invoke("profile", "list", "--json").stdout)
    assert listed_after["profiles"] == []


def test_profile_apply_unknown_errors(sandbox_home):
    result = _invoke("profile", "apply", "does-not-exist")
    assert result.exit_code == 1


def test_schedule_enable_disable_status(sandbox_home, monkeypatch):
    import subprocess

    from filecleaner import schedule as schedule_mod

    monkeypatch.setattr(
        schedule_mod,
        "_launchctl",
        lambda *args: subprocess.CompletedProcess(args=["launchctl", *args], returncode=0, stdout="", stderr=""),
    )

    result = _invoke("schedule", "enable", "--every-hours", "6")
    assert result.exit_code == 0

    status = json.loads(_invoke("schedule", "status", "--json").stdout)
    assert status["installed"] is True

    assert _invoke("schedule", "disable").exit_code == 0
    status_after = json.loads(_invoke("schedule", "status", "--json").stdout)
    assert status_after["installed"] is False


def test_schedule_enable_failure_surfaces_as_cli_error(sandbox_home, monkeypatch):
    import subprocess

    from filecleaner import schedule as schedule_mod

    monkeypatch.setattr(
        schedule_mod,
        "_launchctl",
        lambda *args: subprocess.CompletedProcess(args=["launchctl", *args], returncode=1, stdout="", stderr="boom"),
    )
    result = _invoke("schedule", "enable")
    assert result.exit_code == 1


def test_quarantine_history_json(sandbox_home, tmp_path):
    target = tmp_path / "big.bin"
    target.write_bytes(b"x" * 42)
    from filecleaner import quarantine as quarantine_mod
    from filecleaner.models import Candidate

    cfg = json.loads(_invoke("config", "show", "--json").stdout)["config"]
    quarantine_mod.quarantine_candidates(
        [Candidate(path=target, size_bytes=42, is_dir=False, mtime=0.0, rule_id="r", category="Caches", risk="low")],
        cfg,
    )
    result = _invoke("quarantine", "history", "--json")
    assert result.exit_code == 0
    data = json.loads(result.stdout)
    assert data["by_category"] == [{"category": "Caches", "count": 1, "size_bytes": 42}]
    assert len(data["by_day"]) == 1


def test_large_files_json(sandbox_home, tmp_path):
    big = sandbox_home / "big.bin"
    big.write_bytes(b"x" * 5000)
    result = _invoke("large-files", str(sandbox_home), "--json")
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["files"][0]["path"] == str(big)


def test_duplicates_json(sandbox_home):
    content = b"same content" * 100
    (sandbox_home / "a.bin").write_bytes(content)
    (sandbox_home / "b.bin").write_bytes(content)
    result = _invoke("duplicates", str(sandbox_home), "--json", "--min-size", "10")
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert len(payload["groups"]) == 1
    assert payload["groups"][0]["copies"] == 2


def test_audit_log_records_scan(cache_item, sandbox_home):
    _invoke("scan")
    result = _invoke("audit", "--json")
    payload = json.loads(result.stdout)
    assert any(e["action"] == "scan" for e in payload["entries"])


def test_bracketed_paths_survive_json_round_trip(sandbox_home, age_path):
    weird = sandbox_home / "Library" / "Caches" / "App [Beta]"
    weird.mkdir(parents=True)
    (weird / "data.bin").write_bytes(b"x" * 10)
    age_path(weird, days=10)
    age_path(weird / "data.bin", days=10)

    result = _invoke("scan", "--json")
    payload = json.loads(result.stdout)
    assert payload["candidates"][0]["path"] == str(weird)


def test_restore_filters_by_path_substring(sandbox_home, age_path):
    a = sandbox_home / "Library" / "Caches" / "AppA"
    b = sandbox_home / "Library" / "Caches" / "AppB"
    for d in (a, b):
        d.mkdir(parents=True)
        (d / "f.bin").write_bytes(b"x" * 10)
        age_path(d, days=10)
        age_path(d / "f.bin", days=10)
    _invoke("clean", "--apply", "--yes")

    result = _invoke("restore", "--path", "AppA", "--yes", "--json")
    payload = json.loads(result.stdout)
    assert payload["count"] == 1
    assert "AppA" in payload["entries"][0]["original_path"]
    assert a.exists()
    assert not b.exists()


def test_restore_filters_by_ids(sandbox_home, age_path):
    a = sandbox_home / "Library" / "Caches" / "AppA"
    a.mkdir(parents=True)
    (a / "f.bin").write_bytes(b"x" * 10)
    age_path(a, days=10)
    age_path(a / "f.bin", days=10)
    _invoke("clean", "--apply", "--yes")

    listed = json.loads(_invoke("quarantine", "list", "--json").stdout)
    entry_id = listed["entries"][0]["id"]

    result = _invoke("restore", "--ids", str(entry_id), "--yes", "--json")
    payload = json.loads(result.stdout)
    assert payload["count"] == 1
    assert a.exists()


def test_restore_bad_ids_errors(sandbox_home):
    result = _invoke("restore", "--ids", "not-a-number")
    assert result.exit_code == 1
    assert isinstance(result.exception, cli_mod.CliError)


def test_quarantine_purge_by_session(cache_item, sandbox_home):
    _invoke("clean", "--apply", "--yes")
    sessions = json.loads(_invoke("quarantine", "sessions", "--json").stdout)["sessions"]
    session_id = sessions[0]["session_id"]

    result = _invoke("quarantine", "purge", "--session", session_id, "--yes", "--json")
    payload = json.loads(result.stdout)
    assert payload["count"] == 1
    assert json.loads(_invoke("quarantine", "list", "--json").stdout)["entries"] == []


def test_clean_exclude_flag_skips_path(sandbox_home, age_path):
    keep_me = sandbox_home / "Library" / "Caches" / "KeepMe"
    keep_me.mkdir(parents=True)
    (keep_me / "f.bin").write_bytes(b"x" * 10)
    age_path(keep_me, days=10)
    age_path(keep_me / "f.bin", days=10)

    result = _invoke("scan", "--exclude", str(keep_me), "--json")
    payload = json.loads(result.stdout)
    assert payload["candidate_count"] == 0


def test_config_show_reports_config_error(sandbox_home):
    from filecleaner import config as config_mod

    config_mod.ensure_dirs()
    config_mod.CONFIG_FILE.write_text("not [valid toml")
    result = _invoke("config", "show")
    assert result.exit_code == 1
    assert isinstance(result.exception, cli_mod.CliError)


def test_doctor_reports_filevault_off(sandbox_home, monkeypatch):
    import subprocess

    class FakeCompleted:
        stdout = "FileVault is Off.\n"

    monkeypatch.setattr(subprocess, "run", lambda *a, **k: FakeCompleted())
    result = _invoke("doctor", "--json")
    payload = json.loads(result.stdout)
    assert payload["filevault_on"] is False


def test_doctor_reports_filevault_on(sandbox_home, monkeypatch):
    import subprocess

    class FakeCompleted:
        stdout = "FileVault is On.\n"

    monkeypatch.setattr(subprocess, "run", lambda *a, **k: FakeCompleted())
    result = _invoke("doctor", "--json")
    payload = json.loads(result.stdout)
    assert payload["filevault_on"] is True


def test_doctor_flags_unknown_rule_override(sandbox_home):
    from filecleaner import config as config_mod

    cfg = config_mod.load_config()
    cfg["rule_overrides"]["totally_bogus_rule"] = True
    config_mod.save_config(cfg)

    result = _invoke("doctor")
    assert result.exit_code == 0
    assert "totally_bogus_rule" in result.stdout


class TestBackupsCli:
    @pytest.fixture
    def backup_root(self, sandbox_home):
        import plistlib
        from datetime import datetime, timedelta

        root = sandbox_home / "Library" / "Application Support" / "MobileSync" / "Backup"

        def make(udid, device_name, days_ago):
            d = root / udid
            d.mkdir(parents=True)
            with (d / "Info.plist").open("wb") as f:
                plistlib.dump(
                    {
                        "Device Name": device_name,
                        "Product Type": "iPhone99,1",
                        "Last Backup Date": datetime.now(UTC) - timedelta(days=days_ago),
                    },
                    f,
                )
            (d / "payload.bin").write_bytes(b"x" * 4096)
            return d

        make("udid-old", "My iPhone", days_ago=40)
        make("udid-new", "My iPhone", days_ago=1)
        return root

    def test_backups_list_json(self, backup_root):
        result = _invoke("backups", "list", "--json")
        assert result.exit_code == 0
        payload = json.loads(result.stdout)
        assert len(payload["backups"]) == 2

    def test_backups_clean_dry_run(self, backup_root):
        result = _invoke("backups", "clean", "--json")
        payload = json.loads(result.stdout)
        assert len(payload["backups"]) == 1  # only the stale one, newest kept

    def test_backups_clean_apply(self, backup_root):
        result = _invoke("backups", "clean", "--apply", "--yes", "--json")
        payload = json.loads(result.stdout)
        assert payload["count"] == 1
        assert not (backup_root / "udid-old").exists()
        assert (backup_root / "udid-new").exists()

    def test_backups_list_empty(self, sandbox_home):
        result = _invoke("backups", "list")
        assert result.exit_code == 0
        assert "No local" in result.stdout


class TestDeviceCli:
    def test_device_list_reports_unavailable(self, sandbox_home, monkeypatch):
        from filecleaner import device as device_mod

        def boom():
            raise device_mod.DeviceUnavailable("No iPhone/iPad detected.")

        monkeypatch.setattr(device_mod, "list_devices", boom)
        result = _invoke("device", "list")
        assert result.exit_code == 1
        assert isinstance(result.exception, cli_mod.CliError)

    def test_device_list_json(self, sandbox_home, monkeypatch):
        from filecleaner import device as device_mod

        fake = [device_mod.DeviceInfo(udid="ABCD", name="Test iPhone", product_type="iPhone1,1")]
        monkeypatch.setattr(device_mod, "list_devices", lambda: fake)
        result = _invoke("device", "list", "--json")
        payload = json.loads(result.stdout)
        assert payload["devices"][0]["name"] == "Test iPhone"

    def test_device_apps_json(self, sandbox_home, monkeypatch):
        from filecleaner import device as device_mod

        fake = [device_mod.AppInfo(bundle_id="com.example.app", name="Example", version="1.0", size_bytes=100)]
        monkeypatch.setattr(device_mod, "list_apps", lambda udid, user_apps_only=True: fake)
        result = _invoke("device", "apps", "--json")
        payload = json.loads(result.stdout)
        assert payload["apps"][0]["bundle_id"] == "com.example.app"

    def test_device_uninstall_requires_confirmation(self, sandbox_home, monkeypatch):
        from filecleaner import device as device_mod

        calls = []
        monkeypatch.setattr(device_mod, "uninstall_app", lambda bid, udid=None: calls.append(bid))
        result = _invoke("device", "uninstall", "com.example.app", "--yes")
        assert result.exit_code == 0
        assert calls == ["com.example.app"]

    def test_device_uninstall_without_yes_refuses_non_interactively(self, sandbox_home, monkeypatch):
        from filecleaner import device as device_mod

        calls = []
        monkeypatch.setattr(device_mod, "uninstall_app", lambda bid, udid=None: calls.append(bid))
        result = _invoke("device", "uninstall", "com.example.app")
        assert result.exit_code != 0
        assert calls == []
