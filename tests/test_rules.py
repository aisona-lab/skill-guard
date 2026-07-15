from pathlib import Path

from skill_guard.engine import scan_path
from skill_guard.models import RuleId, Verdict


def test_malicious_secret_blocks(dataset_root: Path):
    r = scan_path(dataset_root / "fixtures/malicious/secret-in-body")
    assert r.verdict is Verdict.BLOCK
    assert any(f.rule_id is RuleId.SG002 for f in r.findings)


def test_malicious_curl_pipe(dataset_root: Path):
    r = scan_path(dataset_root / "fixtures/malicious/curl-pipe-shell")
    assert r.verdict is Verdict.BLOCK
    assert any(f.rule_id is RuleId.SG003 for f in r.findings)


def test_malicious_exfil_env(dataset_root: Path):
    r = scan_path(dataset_root / "fixtures/malicious/env-stealer")
    assert r.verdict is Verdict.BLOCK
    assert any(f.rule_id is RuleId.SG004 for f in r.findings)


def test_multi_file_script_attack(dataset_root: Path):
    """Body is clean; scripts/ holds the malice — package scan must still catch it."""
    r = scan_path(dataset_root / "fixtures/malicious/multi-file-only-script")
    assert r.verdict is Verdict.BLOCK
    paths = {f.path for f in r.findings if f.path}
    assert any("scripts/" in p for p in paths)


def test_benign_allows(dataset_root: Path):
    r = scan_path(dataset_root / "fixtures/benign/tdd-checklist")
    assert r.verdict is Verdict.ALLOW
    assert r.findings == [] or all(f.severity.value == "low" for f in r.findings)


def test_enterprise_metadata(dataset_root: Path):
    r = scan_path(dataset_root / "fixtures/enterprise/cloud-metadata-grab")
    assert r.verdict is Verdict.BLOCK
    assert any(f.rule_id is RuleId.SG010 for f in r.findings)


def test_prompt_hijack(dataset_root: Path):
    r = scan_path(dataset_root / "fixtures/malicious/prompt-hijack")
    assert r.verdict is Verdict.BLOCK
    assert any(f.rule_id is RuleId.SG005 for f in r.findings)


def test_placeholder_api_key_not_critical(dataset_root: Path):
    r = scan_path(dataset_root / "fixtures/borderline/mentions-api-key-docs")
    # Must not BLOCK on documentation placeholders
    assert r.verdict is not Verdict.BLOCK
