"""Production gate: adversarial attack recall must stay above threshold."""

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_adversarial_suite_gate():
    proc = subprocess.run(
        [
            sys.executable,
            str(ROOT / "eval" / "run_eval.py"),
            "--suite",
            "adversarial",
            "--check",
            "--details",
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        env={**dict(__import__("os").environ), "PYTHONPATH": str(ROOT / "src")},
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr


def test_core_and_adversarial_all():
    proc = subprocess.run(
        [sys.executable, str(ROOT / "eval" / "run_eval.py"), "--suite", "all", "--check"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        env={**dict(__import__("os").environ), "PYTHONPATH": str(ROOT / "src")},
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
