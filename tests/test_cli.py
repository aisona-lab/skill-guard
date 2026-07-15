import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _run(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "skill_guard.cli", *args],
        cwd=ROOT,
        capture_output=True,
        text=True,
        env={**dict(**__import__("os").environ), "PYTHONPATH": str(ROOT / "src")},
    )


def test_cli_scan_benign_exit_zero(dataset_root: Path):
    target = dataset_root / "fixtures/benign/pdf-summarize"
    proc = _run("scan", str(target))
    assert proc.returncode == 0, proc.stderr + proc.stdout
    assert "ALLOW" in proc.stdout


def test_cli_scan_malicious_block(dataset_root: Path):
    target = dataset_root / "fixtures/malicious/curl-pipe-shell"
    proc = _run("scan", str(target))
    # default --fail-on block → exit 2
    assert proc.returncode == 2, proc.stderr + proc.stdout
    assert "BLOCK" in proc.stdout


def test_cli_json(dataset_root: Path):
    target = dataset_root / "fixtures/malicious/secret-in-body"
    proc = _run("scan", str(target), "--json")
    assert proc.returncode == 2
    data = json.loads(proc.stdout)
    assert data["verdict"] == "BLOCK"
    assert data["exit_code"] == 2
    assert len(data["findings"]) >= 1


def test_cli_missing_path():
    proc = _run("scan", "/nonexistent/skill-path-xyz")
    assert proc.returncode == 3


def test_cli_sarif_file_single_pass(dataset_root: Path, tmp_path: Path):
    target = dataset_root / "fixtures/malicious/curl-pipe-shell"
    out = tmp_path / "out.sarif"
    proc = _run("scan", str(target), "--sarif-file", str(out))
    assert proc.returncode == 2
    assert "BLOCK" in proc.stdout
    data = json.loads(out.read_text())
    assert data["version"] == "2.1.0"
    assert data["runs"][0]["results"]


def test_cli_multi_target_one_sarif_doc(dataset_root: Path):
    a = dataset_root / "fixtures/benign/tdd-checklist"
    b = dataset_root / "fixtures/malicious/curl-pipe-shell"
    proc = _run("scan", str(a), str(b), "--sarif")
    assert proc.returncode == 2
    data = json.loads(proc.stdout)
    assert data["version"] == "2.1.0"
    assert len(data["runs"]) == 1

