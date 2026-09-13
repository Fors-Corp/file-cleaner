"""Local, online-learning file-category classifier for the organizer.

No ML framework, no training pipeline, no external dataset, no network call
— a hand-rolled multinomial Naive Bayes over hashed filename/extension
tokens, in the spirit of small local statistical classifiers over a heavy
model or a cloud API (the same idea behind log-severity classification in
Forseer, the ML module of the unrelated `forsight` observability project —
that model itself classifies log/metric streams and isn't reusable here,
but its "small local statistical classifier, not a heavy one" approach is).

Cold-start is solved by seeding: the classifier is pre-trained once, at
construction, on ``EXTENSION_PRIORS`` — so it is immediately useful with
zero real examples. Every time a caller (the organizer's dry-run review)
accepts or corrects a suggestion, ``update()`` folds that single example
in, so the model gets better per-user, per-machine, entirely locally —
weights never include a filename or path, only aggregate token counts, and
never leave the machine.
"""

from __future__ import annotations

import json
import math
import re
import zlib
from collections import defaultdict
from pathlib import Path
from typing import Any

CATEGORIES: tuple[str, ...] = (
    "Documents",
    "Spreadsheets",
    "Presentations",
    "Images",
    "Screenshots",
    "Videos",
    "Audio",
    "Archives",
    "Installers",
    "Code",
    "Design",
    "Other",
)

# Extension (lowercase, no leading dot) -> category. Consulted only once, to
# seed the classifier's priors at construction time (see ``_seed``) — not at
# prediction time, so there is exactly one scoring path, not two.
EXTENSION_PRIORS: dict[str, str] = {
    "pdf": "Documents", "doc": "Documents", "docx": "Documents", "txt": "Documents",
    "rtf": "Documents", "pages": "Documents", "md": "Documents", "epub": "Documents",
    "xls": "Spreadsheets", "xlsx": "Spreadsheets", "csv": "Spreadsheets", "numbers": "Spreadsheets",
    "ppt": "Presentations", "pptx": "Presentations", "key": "Presentations",
    "jpg": "Images", "jpeg": "Images", "png": "Images", "heic": "Images", "gif": "Images",
    "webp": "Images", "bmp": "Images", "tiff": "Images", "svg": "Images", "raw": "Images",
    "mp4": "Videos", "mov": "Videos", "avi": "Videos", "mkv": "Videos", "m4v": "Videos", "webm": "Videos",
    "mp3": "Audio", "wav": "Audio", "aac": "Audio", "flac": "Audio", "m4a": "Audio", "aiff": "Audio",
    "zip": "Archives", "tar": "Archives", "gz": "Archives", "7z": "Archives", "rar": "Archives", "bz2": "Archives",
    "dmg": "Installers", "pkg": "Installers", "exe": "Installers", "msi": "Installers",
    "py": "Code", "js": "Code", "ts": "Code", "tsx": "Code", "jsx": "Code", "go": "Code", "rs": "Code",
    "java": "Code", "c": "Code", "cpp": "Code", "h": "Code", "swift": "Code", "sh": "Code",
    "psd": "Design", "ai": "Design", "sketch": "Design", "fig": "Design", "xd": "Design", "indd": "Design",
}

_NUM_BUCKETS = 2048
# Pseudo-count applied per prior extension at seed time: enough that a fresh
# classifier makes sensible guesses immediately, but a handful of real
# `update()` corrections can still outweigh a wrong prior over time.
_SEED_WEIGHT = 6
_TOKEN_RE = re.compile(r"[a-z0-9]+")


def _bucket(token: str) -> int:
    """Stable across processes/restarts (unlike Python's randomized
    built-in ``hash()``), since weights are persisted to disk and reloaded."""
    return zlib.crc32(token.encode("utf-8")) % _NUM_BUCKETS


def tokenize(path: Path) -> list[str]:
    """Filename -> tokens. Filename/extension signal only — file contents
    are never read. The extension is repeated since it's the single
    strongest signal a Naive Bayes bag-of-tokens model can use."""
    ext = path.suffix.lower().lstrip(".")
    stem_tokens = _TOKEN_RE.findall(path.stem.lower())[:8]  # cap: one long name can't dominate
    tokens = list(stem_tokens)
    if ext:
        tokens += [f"ext:{ext}"] * 3
    return tokens


class Classifier:
    """Multinomial Naive Bayes over hashed tokens, Laplace-smoothed."""

    def __init__(self) -> None:
        self.category_doc_counts: dict[str, int] = defaultdict(int)
        self.category_token_totals: dict[str, int] = defaultdict(int)
        self.token_counts: dict[str, dict[int, int]] = {}
        self._seed()

    def _seed(self) -> None:
        for ext, category in EXTENSION_PRIORS.items():
            tokens = [f"ext:{ext}"] * 3
            for _ in range(_SEED_WEIGHT):
                self.update_tokens(tokens, category)

    def update_tokens(self, tokens: list[str], category: str) -> None:
        self.category_doc_counts[category] += 1
        bucket_counts = self.token_counts.setdefault(category, {})
        for tok in tokens:
            b = _bucket(tok)
            bucket_counts[b] = bucket_counts.get(b, 0) + 1
            self.category_token_totals[category] += 1

    def update(self, path: Path, category: str) -> None:
        """Record one real, user-confirmed-or-corrected example."""
        self.update_tokens(tokenize(path), category)

    def predict(self, path: Path) -> tuple[str, float]:
        """Return ``(best_category, confidence)`` with confidence in [0, 1]."""
        scores = self._scores(tokenize(path))
        best = max(scores, key=lambda c: scores[c])
        top = max(scores.values())
        exps = {c: math.exp(s - top) for c, s in scores.items()}
        total = sum(exps.values())
        confidence = exps[best] / total if total else 0.0
        return best, confidence

    def _scores(self, tokens: list[str]) -> dict[str, float]:
        seen_categories = set(self.category_doc_counts) | set(CATEGORIES)
        total_docs = sum(self.category_doc_counts.values()) or 1
        scores: dict[str, float] = {}
        for category in seen_categories:
            doc_count = self.category_doc_counts.get(category, 0)
            log_prior = math.log((doc_count + 1) / (total_docs + len(seen_categories)))
            token_total = self.category_token_totals.get(category, 0)
            bucket_counts = self.token_counts.get(category, {})
            log_likelihood = sum(
                math.log((bucket_counts.get(_bucket(tok), 0) + 1) / (token_total + _NUM_BUCKETS))
                for tok in tokens
            )
            scores[category] = log_prior + log_likelihood
        return scores

    def to_dict(self) -> dict[str, Any]:
        return {
            "num_buckets": _NUM_BUCKETS,
            "category_doc_counts": dict(self.category_doc_counts),
            "category_token_totals": dict(self.category_token_totals),
            "token_counts": {cat: dict(buckets) for cat, buckets in self.token_counts.items()},
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Classifier:
        obj = cls.__new__(cls)
        obj.category_doc_counts = defaultdict(int, data.get("category_doc_counts", {}))
        obj.category_token_totals = defaultdict(int, data.get("category_token_totals", {}))
        obj.token_counts = {
            cat: {int(bucket): count for bucket, count in buckets.items()}
            for cat, buckets in data.get("token_counts", {}).items()
        }
        return obj


def load(path: Path | None = None) -> Classifier:
    from filecleaner import config as config_mod

    target = path or config_mod.get_classifier_path()
    if not target.exists():
        return Classifier()
    try:
        data = json.loads(target.read_text())
    except (OSError, json.JSONDecodeError):
        return Classifier()
    return Classifier.from_dict(data)


def save(classifier: Classifier, path: Path | None = None) -> None:
    import os

    from filecleaner import config as config_mod

    target = path or config_mod.get_classifier_path()
    target.write_text(json.dumps(classifier.to_dict()))
    os.chmod(target, 0o600)
