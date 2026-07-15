"""Production-surface eval gates."""

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ENV = {**dict(__import__("os").environ), "PYTHONPATH": str(ROOT / "src")}


def test_selftest_passes():
    proc = subprocess.run(
        [sys.executable, str(ROOT / "eval" / "selftest.py")],
        cwd=ROOT,
        capture_output=True,
        text=True,
        env=ENV,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr


def test_eval_all_check_passes():
    proc = subprocess.run(
        [sys.executable, str(ROOT / "eval" / "run_eval.py"), "--suite", "all", "--check"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        env=ENV,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
