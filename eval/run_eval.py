"""Dataset eval harness.

Metrics (core tier only for CI gates):
  - unsafe_recall: fraction of label=unsafe fixtures that BLOCK
  - rule_recall: fraction of unsafe fixtures that fire ≥1 expected_rule
  - safe_fpr: fraction of label=safe fixtures that BLOCK (false block rate)

Inspired by OrcaI eval honesty and ponytail selftest discipline.

  uv run python eval/run_eval.py
  uv run python eval/run_eval.py --check
  uv run python eval/run_eval.py --json
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from skill_guard.engine import scan_path  # noqa: E402
from skill_guard.models import Verdict  # noqa: E402

CATALOG = ROOT / "dataset" / "catalog.jsonl"

# Conservative production gates for core tier
MIN_UNSAFE_RECALL = 0.95
MIN_RULE_RECALL = 0.90
MAX_SAFE_FPR = 0.10


def load_catalog() -> list[dict]:
    rows = []
    for line in CATALOG.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        rows.append(json.loads(line))
    return rows


def evaluate(rows: list[dict]) -> dict:
    details = []
    unsafe_total = unsafe_blocked = 0
    rule_hits = rule_total = 0
    safe_total = safe_blocked = 0
    soft_rows = []

    for row in rows:
        path = ROOT / "dataset" / row["path"]
        result = scan_path(path)
        fired = sorted({f.rule_id.value for f in result.findings})
        entry = {
            "id": row["id"],
            "label": row["label"],
            "tier": row.get("tier", "core"),
            "expected_verdict": row["expected_verdict"],
            "actual_verdict": result.verdict.value,
            "expected_rules": row.get("expected_rules", []),
            "fired_rules": fired,
            "finding_count": len(result.findings),
        }
        details.append(entry)

        if row.get("tier") == "soft" or row["label"] == "borderline":
            soft_rows.append(entry)
            continue

        if row["label"] == "unsafe":
            unsafe_total += 1
            if result.verdict is Verdict.BLOCK:
                unsafe_blocked += 1
            expected = set(row.get("expected_rules") or [])
            if expected:
                rule_total += 1
                if expected & set(fired):
                    rule_hits += 1
        elif row["label"] == "safe":
            safe_total += 1
            if result.verdict is Verdict.BLOCK:
                safe_blocked += 1

    metrics = {
        "unsafe_total": unsafe_total,
        "unsafe_blocked": unsafe_blocked,
        "unsafe_recall": (unsafe_blocked / unsafe_total) if unsafe_total else 1.0,
        "rule_total": rule_total,
        "rule_hits": rule_hits,
        "rule_recall": (rule_hits / rule_total) if rule_total else 1.0,
        "safe_total": safe_total,
        "safe_blocked": safe_blocked,
        "safe_fpr": (safe_blocked / safe_total) if safe_total else 0.0,
        "soft_count": len(soft_rows),
    }
    return {"metrics": metrics, "details": details, "soft": soft_rows}


def gates_ok(metrics: dict) -> list[str]:
    fails = []
    if metrics["unsafe_recall"] < MIN_UNSAFE_RECALL:
        fails.append(
            f"unsafe_recall {metrics['unsafe_recall']:.3f} < {MIN_UNSAFE_RECALL}"
        )
    if metrics["rule_recall"] < MIN_RULE_RECALL:
        fails.append(f"rule_recall {metrics['rule_recall']:.3f} < {MIN_RULE_RECALL}")
    if metrics["safe_fpr"] > MAX_SAFE_FPR:
        fails.append(f"safe_fpr {metrics['safe_fpr']:.3f} > {MAX_SAFE_FPR}")
    return fails


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="skill-guard dataset eval")
    ap.add_argument("--check", action="store_true", help="exit 1 if gates fail")
    ap.add_argument("--json", action="store_true", help="JSON output")
    ap.add_argument("--details", action="store_true", help="print per-fixture rows")
    args = ap.parse_args(argv)

    if not CATALOG.is_file():
        print(f"error: missing catalog {CATALOG}", file=sys.stderr)
        return 2

    report = evaluate(load_catalog())
    m = report["metrics"]

    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print("skill-guard eval (core tier)")
        print(
            f"  unsafe_recall: {m['unsafe_recall']:.3f} "
            f"({m['unsafe_blocked']}/{m['unsafe_total']})"
        )
        print(
            f"  rule_recall:   {m['rule_recall']:.3f} "
            f"({m['rule_hits']}/{m['rule_total']})"
        )
        print(
            f"  safe_fpr:      {m['safe_fpr']:.3f} "
            f"({m['safe_blocked']}/{m['safe_total']} blocked)"
        )
        print(f"  soft rows:     {m['soft_count']} (not gated)")
        if args.details:
            for d in report["details"]:
                mark = "ok"
                if d["tier"] == "core" and d["label"] == "unsafe" and d["actual_verdict"] != "BLOCK":
                    mark = "MISS"
                if d["tier"] == "core" and d["label"] == "safe" and d["actual_verdict"] == "BLOCK":
                    mark = "FP"
                print(
                    f"  [{mark}] {d['id']}: {d['actual_verdict']} "
                    f"rules={d['fired_rules']}"
                )

    fails = gates_ok(m)
    if args.check and fails:
        print("GATE FAIL:", file=sys.stderr)
        for f in fails:
            print(f"  - {f}", file=sys.stderr)
        return 1
    if args.check:
        print("GATE PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
