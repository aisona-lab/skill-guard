"""Production-surface eval gate: dataset metrics must stay green."""

import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_selftest_passes():
    proc = subprocess.run(
        [sys.executable, str(ROOT / "eval" / "selftest.py")],
        cwd=ROOT,
        capture_output=True,
        text=True,
        env={**dict(__import__("os").environ), "PYTHONPATH": str(ROOT / "src")},
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr


def test_eval_check_passes():
    proc = subprocess.run(
        [sys.executable, str(ROOT / "eval" / "run_eval.py"), "--check", "--json"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        env={**dict(__import__("os").environ), "PYTHONPATH": str(ROOT / "src")},
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    # last JSON object may be mixed with GATE PASS — parse from stdout carefully
    text = proc.stdout
    # When --json, full report is printed; GATE PASS after
    start = text.find("{")
    end = text.rfind("}") + 1
    report = json.loads(text[start:end])
    m = report["metrics"]
    assert m["unsafe_recall"] >= 0.95
    assert m["safe_fpr"] <= 0.10
