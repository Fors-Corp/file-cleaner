import os
import plistlib

from filecleaner import leftovers


def _make_app(apps_dir, name, bundle_id):
    app = apps_dir / f"{name}.app"
    contents = app / "Contents"
    contents.mkdir(parents=True)
    with (contents / "Info.plist").open("wb") as f:
        plistlib.dump({"CFBundleIdentifier": bundle_id}, f)
    return app


class TestInstalledApps:
    def test_reads_bundle_id_and_name(self, tmp_path, monkeypatch):
        apps_dir = tmp_path / "Applications"
        apps_dir.mkdir()
        _make_app(apps_dir, "CoolApp", "com.example.coolapp")
        monkeypatch.setattr(leftovers, "_APPLICATIONS_DIRS", (apps_dir,))

        bundle_ids, names = leftovers.installed_apps()

        assert "com.example.coolapp" in bundle_ids
        assert "CoolApp" in names

    def test_missing_applications_dir_is_harmless(self, tmp_path, monkeypatch):
        monkeypatch.setattr(leftovers, "_APPLICATIONS_DIRS", (tmp_path / "does-not-exist",))
        bundle_ids, names = leftovers.installed_apps()
        assert bundle_ids == set()
        assert names == set()


class TestAppLeftovers:
    def test_flags_orphaned_folder(self, tmp_path, sandbox_config, monkeypatch, age_path):
        apps_dir = tmp_path / "Applications"
        apps_dir.mkdir()
        monkeypatch.setattr(leftovers, "_APPLICATIONS_DIRS", (apps_dir,))

        home = tmp_path / "home"
        orphan = home / "Library" / "Application Support" / "com.example.uninstalled"
        orphan.mkdir(parents=True)
        (orphan / "data.bin").write_bytes(b"x" * 1000)
        age_path(orphan, days=60)
        age_path(orphan / "data.bin", days=60)

        candidates = leftovers.find_app_leftovers(sandbox_config, home=home, min_age_days=30)

        assert len(candidates) == 1
        assert candidates[0].path == orphan
        assert candidates[0].risk == "high"
        assert candidates[0].category == leftovers._APP_LEFTOVERS_CATEGORY

    def test_does_not_flag_installed_app_folder(self, tmp_path, sandbox_config, monkeypatch, age_path):
        apps_dir = tmp_path / "Applications"
        apps_dir.mkdir()
        _make_app(apps_dir, "CoolApp", "com.example.coolapp")
        monkeypatch.setattr(leftovers, "_APPLICATIONS_DIRS", (apps_dir,))

        home = tmp_path / "home"
        support = home / "Library" / "Application Support" / "com.example.coolapp"
        support.mkdir(parents=True)
        age_path(support, days=60)

        candidates = leftovers.find_app_leftovers(sandbox_config, home=home, min_age_days=30)

        assert candidates == []

    def test_respects_min_age(self, tmp_path, sandbox_config, monkeypatch):
        apps_dir = tmp_path / "Applications"
        apps_dir.mkdir()
        monkeypatch.setattr(leftovers, "_APPLICATIONS_DIRS", (apps_dir,))

        home = tmp_path / "home"
        fresh_orphan = home / "Library" / "Caches" / "com.example.fresh"
        fresh_orphan.mkdir(parents=True)  # left at current mtime

        candidates = leftovers.find_app_leftovers(sandbox_config, home=home, min_age_days=30)

        assert candidates == []


class TestInstallerCleanup:
    def test_flags_installer_with_matching_installed_app(self, tmp_path, sandbox_config, monkeypatch):
        apps_dir = tmp_path / "Applications"
        apps_dir.mkdir()
        _make_app(apps_dir, "CoolApp", "com.example.coolapp")
        monkeypatch.setattr(leftovers, "_APPLICATIONS_DIRS", (apps_dir,))

        downloads = tmp_path / "Downloads"
        downloads.mkdir()
        installer = downloads / "CoolApp.dmg"
        installer.write_bytes(b"x" * 1000)

        candidates = leftovers.find_installer_cleanup(sandbox_config, downloads=downloads)

        assert len(candidates) == 1
        assert candidates[0].path == installer
        assert candidates[0].category == leftovers._INSTALLER_CLEANUP_CATEGORY

    def test_flags_installer_with_already_extracted_sibling(self, tmp_path, sandbox_config, monkeypatch):
        monkeypatch.setattr(leftovers, "_APPLICATIONS_DIRS", (tmp_path / "no-apps",))
        downloads = tmp_path / "Downloads"
        downloads.mkdir()
        (downloads / "myproject.zip").write_bytes(b"x" * 1000)
        (downloads / "myproject").mkdir()

        candidates = leftovers.find_installer_cleanup(sandbox_config, downloads=downloads)

        assert len(candidates) == 1
        assert candidates[0].path == downloads / "myproject.zip"

    def test_does_not_flag_installer_with_no_evidence_of_use(self, tmp_path, sandbox_config, monkeypatch):
        monkeypatch.setattr(leftovers, "_APPLICATIONS_DIRS", (tmp_path / "no-apps",))
        downloads = tmp_path / "Downloads"
        downloads.mkdir()
        (downloads / "SomethingNew.pkg").write_bytes(b"x" * 1000)

        candidates = leftovers.find_installer_cleanup(sandbox_config, downloads=downloads)

        assert candidates == []

    def test_ignores_non_installer_extensions(self, tmp_path, sandbox_config, monkeypatch):
        apps_dir = tmp_path / "Applications"
        apps_dir.mkdir()
        _make_app(apps_dir, "CoolApp", "com.example.coolapp")
        monkeypatch.setattr(leftovers, "_APPLICATIONS_DIRS", (apps_dir,))
        downloads = tmp_path / "Downloads"
        downloads.mkdir()
        (downloads / "CoolApp.txt").write_bytes(b"x")

        candidates = leftovers.find_installer_cleanup(sandbox_config, downloads=downloads)

        assert candidates == []


class TestDamagedAndInterrupted:
    def test_an_app_whose_info_plist_is_damaged_is_known_by_name(self, tmp_path, monkeypatch):
        """A truncated XML plist used to escape as an ``ExpatError`` and take
        ``fclean leftovers`` down with it."""
        apps_dir = tmp_path / "Applications"
        _make_app(apps_dir, "Whole", "com.example.whole")
        damaged = _make_app(apps_dir, "Damaged", "com.example.damaged")
        (damaged / "Contents" / "Info.plist").write_bytes(b"<plist>truncated")
        monkeypatch.setattr(leftovers, "_APPLICATIONS_DIRS", (apps_dir,))

        bundle_ids, names = leftovers.installed_apps()

        assert bundle_ids == {"com.example.whole"} and names == {"Whole", "Damaged"}

    def test_an_interrupted_listing_of_a_library_folder_is_retried(self, tmp_path, sandbox_config, monkeypatch, age_path):
        """``~/Library/Containers`` is where macOS interrupts listings (see
        ``listing``); unretried, every leftover in the folder went unseen."""
        monkeypatch.setattr(leftovers, "_APPLICATIONS_DIRS", (tmp_path / "no-apps",))
        orphan = tmp_path / "home" / "Library" / "Containers" / "com.gone.app"
        orphan.mkdir(parents=True)
        (orphan / "data").write_bytes(b"x" * 50)
        age_path(orphan / "data", 90)
        age_path(orphan, 90)
        real, failures = os.scandir, []

        def scandir(path):
            if str(path).endswith("/Containers") and len(failures) < 3:
                failures.append(path)
                raise InterruptedError(4, "Interrupted system call")
            return real(path)

        monkeypatch.setattr(os, "scandir", scandir)

        found = leftovers.find_app_leftovers(sandbox_config, home=tmp_path / "home")

        assert [c.path.name for c in found] == ["com.gone.app"] and len(failures) == 3
