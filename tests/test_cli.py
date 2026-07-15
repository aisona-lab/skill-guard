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
