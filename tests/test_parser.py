from pathlib import Path

from skill_guard.parser.package import load_package, parse_skill_md


def test_parse_skill_md_ok():
    content = "---\nname: demo\ndescription: A demo skill for parser unit tests here.\n---\n\n# Body\n"
    fm, body, err = parse_skill_md(content)
    assert err is None
    assert fm["name"] == "demo"
    assert "Body" in body


def test_parse_skill_md_missing_frontmatter():
    fm, body, err = parse_skill_md("# no frontmatter\n")
    assert err is not None
    assert fm == {}


def test_load_package_fixture(dataset_root: Path):
    pkg = load_package(dataset_root / "fixtures/benign/pdf-summarize")
    assert pkg.name == "pdf-summarize"
    assert pkg.skill_md is not None
    assert not pkg.parse_errors
