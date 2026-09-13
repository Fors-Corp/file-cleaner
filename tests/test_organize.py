from pathlib import Path

import pytest

from filecleaner import classify, organize


def _touch(*paths: Path) -> None:
    for p in paths:
        p.parent.mkdir(parents=True, exist_ok=True)
        p.touch()


class TestProposeMoves:
    def test_dry_run_never_touches_filesystem(self, tmp_path, sandbox_config):
        _touch(tmp_path / "invoice.pdf")
        moves = organize.propose_moves(tmp_path, sandbox_config)
        assert (tmp_path / "invoice.pdf").exists()
        assert len(moves) == 1
        assert moves[0].category == "Documents"
        assert moves[0].destination == tmp_path / "Documents" / "invoice.pdf"

    def test_existing_subfolders_are_never_touched(self, tmp_path, sandbox_config):
        _touch(tmp_path / "MyProject" / "notes.txt")
        moves = organize.propose_moves(tmp_path, sandbox_config)
        assert moves == []

    def test_skips_ds_store_and_dotfiles(self, tmp_path, sandbox_config):
        _touch(tmp_path / ".DS_Store", tmp_path / ".hidden")
        moves = organize.propose_moves(tmp_path, sandbox_config)
        assert moves == []

    def test_unknown_extension_uses_classifier_with_confidence(self, tmp_path, sandbox_config):
        _touch(tmp_path / "mystery_thing")
        moves = organize.propose_moves(tmp_path, sandbox_config)
        assert len(moves) == 1
        assert moves[0].reason.startswith("classifier")
        assert moves[0].confidence < 1.0

    def test_invalid_mode_raises(self, tmp_path, sandbox_config):
        with pytest.raises(organize.OrganizeError):
            organize.propose_moves(tmp_path, sandbox_config, mode="bogus")


class TestDateMode:
    def test_date_only_groups_by_year_month(self, tmp_path, sandbox_config, age_path):
        target = tmp_path / "old_note.txt"
        _touch(target)
        age_path(target, days=400)
        moves = organize.propose_moves(tmp_path, sandbox_config, mode="date-only", cluster_projects=False)
        assert len(moves) == 1
        assert moves[0].destination.parent.parent.parent == tmp_path

    def test_date_mode_nests_under_category(self, tmp_path, sandbox_config, age_path):
        target = tmp_path / "invoice.pdf"
        _touch(target)
        moves = organize.propose_moves(tmp_path, sandbox_config, mode="date", cluster_projects=False)
        assert len(moves) == 1
        assert moves[0].destination.parts[-4] == "Documents"


class TestProjectClustering:
    def test_versioned_files_cluster_together(self, tmp_path, sandbox_config):
        _touch(tmp_path / "report.docx", tmp_path / "report_v2.docx", tmp_path / "report copy.docx")
        moves = organize.propose_moves(tmp_path, sandbox_config)
        assert all(m.category == "Projects" for m in moves)
        assert len({m.destination.parent for m in moves}) == 1
        assert all("cluster:" in m.reason for m in moves)

    def test_sequential_numeric_names_do_not_falsely_cluster(self, tmp_path, sandbox_config):
        """The specific bug this guards against: IMG_1234.jpg / IMG_1235.jpg
        are unrelated camera exports, not versions of the same file — a
        naive trailing-number strip would wrongly merge them."""
        _touch(tmp_path / "IMG_1234.jpg", tmp_path / "IMG_1235.jpg")
        moves = organize.propose_moves(tmp_path, sandbox_config)
        assert all(m.category == "Images" for m in moves)
        assert all(m.reason == "extension" for m in moves)

    def test_single_file_does_not_cluster_alone(self, tmp_path, sandbox_config):
        _touch(tmp_path / "report_final.docx")
        moves = organize.propose_moves(tmp_path, sandbox_config)
        assert len(moves) == 1
        assert moves[0].category == "Documents"

    def test_disabled_clustering_falls_back_to_type(self, tmp_path, sandbox_config):
        _touch(tmp_path / "report.docx", tmp_path / "report_v2.docx")
        moves = organize.propose_moves(tmp_path, sandbox_config, cluster_projects=False)
        assert all(m.category == "Documents" for m in moves)


class TestScreenshots:
    def test_recognizes_modern_screenshot_naming(self, tmp_path, sandbox_config):
        _touch(tmp_path / "Screenshot 2026-09-13 at 10.32.45 AM.png")
        moves = organize.propose_moves(tmp_path, sandbox_config)
        assert len(moves) == 1
        assert moves[0].category == "Screenshots"
        assert moves[0].reason == "screenshot"

    def test_recognizes_legacy_screen_shot_naming(self, tmp_path, sandbox_config):
        _touch(tmp_path / "Screen Shot 2020-01-05 at 3.15.02 PM.png")
        moves = organize.propose_moves(tmp_path, sandbox_config)
        assert moves[0].category == "Screenshots"

    def test_regular_png_is_not_misdetected_as_screenshot(self, tmp_path, sandbox_config):
        _touch(tmp_path / "vacation.png")
        moves = organize.propose_moves(tmp_path, sandbox_config)
        assert moves[0].category == "Images"


class TestApplyAndUndo:
    def test_apply_moves_files_and_records_session(self, tmp_path, sandbox_config):
        target = tmp_path / "invoice.pdf"
        _touch(target)
        moves = organize.propose_moves(tmp_path, sandbox_config)

        result = organize.apply_moves(moves, sandbox_config)

        assert not target.exists()
        assert (tmp_path / "Documents" / "invoice.pdf").exists()
        assert len(result.entries) == 1
        assert result.session_id is not None

    def test_apply_skips_missing_source(self, tmp_path, sandbox_config):
        target = tmp_path / "invoice.pdf"
        _touch(target)
        moves = organize.propose_moves(tmp_path, sandbox_config)
        target.unlink()

        result = organize.apply_moves(moves, sandbox_config)
        assert result.entries == []
        assert len(result.skipped) == 1

    def test_apply_skips_existing_destination(self, tmp_path, sandbox_config):
        target = tmp_path / "invoice.pdf"
        _touch(target)
        moves = organize.propose_moves(tmp_path, sandbox_config)
        _touch(moves[0].destination)  # something already there

        result = organize.apply_moves(moves, sandbox_config)
        assert result.entries == []
        assert result.skipped[0].reason == "destination already exists"

    def test_undo_restores_original_locations(self, tmp_path, sandbox_config):
        target = tmp_path / "invoice.pdf"
        _touch(target)
        moves = organize.propose_moves(tmp_path, sandbox_config)
        result = organize.apply_moves(moves, sandbox_config)

        undo = organize.undo_session(result.session_id, sandbox_config)

        assert target.exists()
        assert not (tmp_path / "Documents" / "invoice.pdf").exists()
        assert len(undo.entries) == 1
        assert undo.entries[0].undone is True

    def test_undo_unknown_session_raises(self, sandbox_config):
        with pytest.raises(organize.OrganizeError):
            organize.undo_session("does-not-exist", sandbox_config)

    def test_undo_is_idempotent_after_first_call(self, tmp_path, sandbox_config):
        target = tmp_path / "invoice.pdf"
        _touch(target)
        moves = organize.propose_moves(tmp_path, sandbox_config)
        result = organize.apply_moves(moves, sandbox_config)
        organize.undo_session(result.session_id, sandbox_config)

        with pytest.raises(organize.OrganizeError):
            organize.undo_session(result.session_id, sandbox_config)


class TestListSessions:
    def test_lists_session_with_counts(self, tmp_path, sandbox_config):
        _touch(tmp_path / "invoice.pdf", tmp_path / "vacation.heic")
        moves = organize.propose_moves(tmp_path, sandbox_config)
        result = organize.apply_moves(moves, sandbox_config)

        sessions = organize.list_sessions(sandbox_config)

        assert len(sessions) == 1
        assert sessions[0]["session_id"] == result.session_id
        assert sessions[0]["count"] == 2
        assert sessions[0]["active"] == 2

    def test_undo_reduces_active_count(self, tmp_path, sandbox_config):
        _touch(tmp_path / "invoice.pdf")
        moves = organize.propose_moves(tmp_path, sandbox_config)
        result = organize.apply_moves(moves, sandbox_config)
        organize.undo_session(result.session_id, sandbox_config)

        sessions = organize.list_sessions(sandbox_config)
        assert sessions[0]["active"] == 0

    def test_no_sessions_returns_empty_list(self, sandbox_config):
        assert organize.list_sessions(sandbox_config) == []


class TestClassifierIntegration:
    def test_uses_provided_classifier_instance(self, tmp_path, sandbox_config):
        clf = classify.Classifier()
        clf.update(Path("mystery_thing"), "Design")
        for _ in range(20):
            clf.update(Path("mystery_thing"), "Design")

        _touch(tmp_path / "mystery_thing")
        moves = organize.propose_moves(tmp_path, sandbox_config, classifier=clf)
        assert moves[0].category == "Design"
