from pathlib import Path

from filecleaner import classify


class TestPriors:
    def test_known_extension_predicts_confidently(self):
        c = classify.Classifier()
        category, confidence = c.predict(Path("invoice.pdf"))
        assert category == "Documents"
        assert confidence > 0.9

    def test_extensionless_file_is_low_confidence(self):
        c = classify.Classifier()
        _category, confidence = c.predict(Path("mystery_no_extension_at_all"))
        assert confidence < 0.5

    def test_every_prior_extension_predicts_its_mapped_category(self):
        c = classify.Classifier()
        for ext, expected_category in classify.EXTENSION_PRIORS.items():
            category, _confidence = c.predict(Path(f"file.{ext}"))
            assert category == expected_category, f"{ext} predicted {category}, expected {expected_category}"


class TestOnlineLearning:
    def test_update_shifts_future_predictions(self):
        c = classify.Classifier()
        before_category, _ = c.predict(Path("weird_thing"))
        for _ in range(10):
            c.update(Path("weird_thing"), "Design")
        after_category, after_confidence = c.predict(Path("weird_thing"))
        assert after_category == "Design"
        assert after_confidence > 0.5

    def test_a_few_corrections_do_not_override_a_strong_prior(self):
        """A handful of accidental corrections shouldn't flip a well-seeded
        extension prior — the seed weight should dominate until there's
        real, sustained evidence otherwise."""
        c = classify.Classifier()
        c.update(Path("oops.pdf"), "Images")
        category, _confidence = c.predict(Path("another.pdf"))
        assert category == "Documents"


class TestTokenize:
    def test_extension_and_stem_words_present(self):
        tokens = classify.tokenize(Path("Quarterly Report 2026.pdf"))
        assert "ext:pdf" in tokens
        assert "quarterly" in tokens
        assert "report" in tokens

    def test_long_stem_is_capped(self):
        long_name = "_".join(f"word{i}" for i in range(50)) + ".txt"
        tokens = classify.tokenize(Path(long_name))
        # 8 stem tokens (capped) + 3 repeated extension tokens
        assert len(tokens) == 11


class TestPersistence:
    def test_round_trip_preserves_predictions(self):
        c = classify.Classifier()
        c.update(Path("custom_thing"), "Design")
        reloaded = classify.Classifier.from_dict(c.to_dict())
        assert reloaded.predict(Path("custom_thing")) == c.predict(Path("custom_thing"))
        assert reloaded.predict(Path("invoice.pdf"))[0] == "Documents"

    def test_save_and_load_from_disk(self, tmp_path):
        path = tmp_path / "classifier.json"
        c = classify.Classifier()
        c.update(Path("custom_thing"), "Design")
        classify.save(c, path)

        loaded = classify.load(path)
        assert loaded.predict(Path("custom_thing"))[0] == "Design"
        # 0600 permissions: owner read/write only.
        assert (path.stat().st_mode & 0o777) == 0o600

    def test_load_missing_file_returns_fresh_classifier(self, tmp_path):
        loaded = classify.load(tmp_path / "does-not-exist.json")
        category, confidence = loaded.predict(Path("invoice.pdf"))
        assert category == "Documents"
        assert confidence > 0.9

    def test_load_corrupt_file_returns_fresh_classifier(self, tmp_path):
        path = tmp_path / "classifier.json"
        path.write_text("not valid json{{{")
        loaded = classify.load(path)
        assert loaded.predict(Path("invoice.pdf"))[0] == "Documents"
