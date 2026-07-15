"""OOD suite: real-world safe skills must not false-BLOCK above threshold."""

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ENV = {**dict(__import__("os").environ), "PYTHONPATH": str(ROOT / "src")}


def test_ood_catalog_exists_and_large_enough():
    cat = ROOT / "dataset" / "ood_catalog.jsonl"
    assert cat.is_file()
    rows = [ln for ln in cat.read_text().splitlines() if ln.strip()]
    assert len(rows) >= 40


def test_ood_gate():
    proc = subprocess.run(
        [
            sys.executable,
            str(ROOT / "eval" / "run_eval.py"),
            "--suite",
            "ood",
            "--check",
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        env=ENV,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr


def test_all_suites_including_ood():
    proc = subprocess.run(
        [
            sys.executable,
            str(ROOT / "eval" / "run_eval.py"),
            "--suite",
            "all",
            "--check",
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        env=ENV,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
