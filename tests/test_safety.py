from pathlib import Path

from filecleaner import safety


def test_system_paths_are_protected():
    assert safety.is_protected(Path("/System/Library/CoreServices"))
    assert safety.is_protected(Path("/usr/bin/python3"))
    assert safety.is_protected(Path("/bin/bash"))
    assert safety.is_protected(Path("/Library/Apple/System"))


def test_ordinary_home_path_is_not_protected(tmp_path):
    candidate = tmp_path / "Library" / "Caches" / "SomeApp"
    candidate.mkdir(parents=True)
    assert not safety.is_protected(candidate)


def test_extra_protected_paths_from_config(tmp_path):
    important = tmp_path / "important_project"
    important.mkdir()
    assert not safety.is_protected(important)
    assert safety.is_protected(important, extra_protected=(important,))


def test_is_within_allowed_roots(tmp_path):
    root = tmp_path / "root"
    root.mkdir()
    inside = root / "sub" / "file.txt"
    inside.parent.mkdir(parents=True)
    inside.write_text("x")
    outside = tmp_path / "elsewhere"
    outside.mkdir()

    assert safety.is_within_allowed_roots(inside, (root,))
    assert not safety.is_within_allowed_roots(outside, (root,))
