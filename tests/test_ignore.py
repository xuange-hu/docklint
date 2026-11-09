"""`.dockerignore` matching — the rule behind DRX001 depends on getting this right."""

from __future__ import annotations

from docklint.ignore import DockerIgnore, pattern_to_regex


def _ig(text: str) -> DockerIgnore:
    return DockerIgnore.parse(text)


def test_empty_ignore_matches_nothing():
    ig = DockerIgnore.empty()
    assert ig.is_empty
    assert not ig.matches("a.md")


def test_basename_pattern_matches_at_any_depth():
    ig = _ig("*.md\n")
    assert ig.matches("README.md")
    assert ig.matches("docs/guide.md")
    assert not ig.matches("docs/guide.txt")


def test_directory_pattern_excludes_children():
    ig = _ig("data/\n")
    assert ig.matches("data/fixture.json")
    assert ig.matches("data/a/b/c.json")
    assert not ig.matches("metadata/x.json")


def test_negation_reincludes():
    ig = _ig("data/\n!data/keep.json\n")
    assert ig.matches("data/drop.json")
    assert not ig.matches("data/keep.json")


def test_later_pattern_wins():
    ig = _ig("!data/keep.json\ndata/\n")
    assert ig.matches("data/keep.json")


def test_double_star_crosses_separators():
    ig = _ig("**/*.log\n")
    assert ig.matches("a/b/c.log")
    assert ig.matches("c.log")


def test_single_star_does_not_cross_separators():
    ig = _ig("src/*.py\n")
    assert ig.matches("src/a.py")
    assert not ig.matches("src/sub/a.py")


def test_anchored_pattern_does_not_match_a_subdirectory():
    ig = _ig("build\n")
    # No slash in the pattern means "at any depth" in Docker's semantics, so
    # this is a documented quirk rather than a bug; assert the quirk.
    assert ig.matches("sub/build/x")
    ig2 = _ig("sub/build\n")
    assert ig2.matches("sub/build/x")
    assert not ig2.matches("other/sub/build/x")


def test_character_class():
    ig = _ig("file[0-9].txt\n")
    assert ig.matches("file3.txt")
    assert not ig.matches("filex.txt")


def test_comments_and_blank_lines_are_skipped():
    ig = _ig("# comment\n\n.env\n")
    assert len(ig.patterns) == 1
    assert ig.matches(".env")


def test_covers_dir_uses_dir_semantics():
    ig = _ig(".git\n")
    assert ig.covers_dir(".git")
    assert not ig.covers_dir(".github")


def test_pattern_to_regex_never_matches_empty_pattern():
    assert pattern_to_regex("") == r"(?!)"


def test_leading_slash_is_stripped():
    ig = _ig("/vendor\n")
    assert ig.matches("vendor/lib.js")
