from skill_guard.models import RuleId, Severity, make_finding


def test_make_finding_message_without_path_keeps_explicit_message():
    f = make_finding(
        RuleId.SG008,
        Severity.MEDIUM,
        title="t",
        message="explicit",
        path=None,
    )
    assert f.message == "explicit"


def test_make_finding_default_message_with_path():
    f = make_finding(RuleId.SG001, Severity.LOW, title="Short title", path="SKILL.md")
    assert "SKILL.md" in f.message
    assert "Short title" in f.message


def test_make_finding_truncates_evidence():
    f = make_finding(
        RuleId.SG002,
        Severity.CRITICAL,
        title="t",
        path="a.py",
        evidence="x" * 200,
    )
    assert f.evidence is not None
    assert len(f.evidence) <= 120
