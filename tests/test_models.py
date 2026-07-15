from skill_guard.models import Finding, RuleId, Severity, Verdict, aggregate_verdict


def test_aggregate_empty_allow():
    assert aggregate_verdict([]) is Verdict.ALLOW


def test_aggregate_high_blocks():
    f = Finding(
        rule_id=RuleId.SG002,
        severity=Severity.HIGH,
        title="t",
        message="m",
    )
    assert aggregate_verdict([f]) is Verdict.BLOCK


def test_aggregate_medium_warns():
    f = Finding(
        rule_id=RuleId.SG008,
        severity=Severity.MEDIUM,
        title="t",
        message="m",
    )
    assert aggregate_verdict([f]) is Verdict.WARN


def test_aggregate_low_allows():
    f = Finding(
        rule_id=RuleId.SG001,
        severity=Severity.LOW,
        title="t",
        message="m",
    )
    assert aggregate_verdict([f]) is Verdict.ALLOW


def test_finding_redact_long_evidence():
    f = Finding(
        rule_id=RuleId.SG002,
        severity=Severity.CRITICAL,
        title="t",
        message="m",
        evidence="x" * 200,
    )
    r = f.redacted()
    assert len(r.evidence or "") <= 120
