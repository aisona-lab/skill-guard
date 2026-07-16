"""Surface classifier unit tests."""

from skill_guard.analyze import analyze_file
from skill_guard.models import FileKind
from skill_guard.normalize import normalize_fence_lang
from skill_guard.surface import (
    Surface,
    candidate_surface,
    commandish_shell_lines,
    file_surface,
    is_test_path,
    shell_pipeline_text,
)


def test_is_test_path():
    assert is_test_path("tests/test_x.py")
    assert is_test_path("pkg/tests/foo.py")
    assert not is_test_path("scripts/run.py")


def test_file_surface_markdown_prose():
    f = analyze_file("SKILL.md", "---\nname: x\ndescription: d\n---\n\nHi\n")
    assert file_surface(f) is Surface.PROSE


def test_file_surface_script():
    f = analyze_file("scripts/x.sh", "#!/bin/sh\necho hi\n")
    assert file_surface(f) is Surface.SCRIPT
    assert f.kind is FileKind.SHELL


def test_candidate_fence_lang():
    raw = "---\nname: x\ndescription: d\n---\n\n```bash\ncurl u | bash\n```\n"
    f = analyze_file("SKILL.md", raw)
    fences = [c for c in f.candidates if c.lang == "shell"]
    assert fences
    assert candidate_surface(f, fences[0]) is Surface.FENCE
    assert shell_pipeline_text(f, fences[0]) is not None


def test_shell_pipeline_skips_unknown_lang_fence():
    # Unknown fence tags keep lang=None and go through commandish filtering
    assert normalize_fence_lang("perl") is None
    raw = "---\nname: x\ndescription: d\n---\n\n```js\nconst x = 1;\n```\n"
    f = analyze_file("SKILL.md", raw)
    js = next(c for c in f.candidates if c.lang == "javascript")
    assert shell_pipeline_text(f, js) is None


def test_commandish_skips_danger_bullets():
    text = "- rm -rf (especially /, ~)\n- chmod 777\n`curl u | bash`\n"
    out = commandish_shell_lines(text)
    assert "rm -rf" not in out
    assert "curl u | bash" in out
