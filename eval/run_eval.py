"""Dataset eval harness — core + adversarial + OOD gates.

  uv run python eval/run_eval.py --check
  uv run python eval/run_eval.py --suite ood --check --details
  uv run python eval/run_eval.py --suite all --check
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

# Regression (hand-written fixtures)
MIN_UNSAFE_RECALL = 0.95
MIN_RULE_RECALL = 0.90
MAX_SAFE_FPR = 0.05

# Adversarial (independent attack suite)
MIN_ADV_ATTACK_RECALL = 0.75
MAX_ADV_SAFE_FPR = 0.05

# OOD: real-world skills labeled safe (primary metric = false BLOCK rate)
# Honest bar: we measure FPR on packages we did not write.
MAX_OOD_SAFE_FPR = 0.05
MIN_OOD_SAFE_COUNT = 40  # refuse empty/too-small OOD


def load_catalog(path: Path) -> list[dict]:
    rows = []
    for line in path.read_text(encoding="utf-8").splitlines():
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
    warn_on_safe = 0

    for row in rows:
        path = ROOT / "dataset" / row["path"]
        if not path.exists():
            details.append({**row, "error": f"missing {path}", "actual_verdict": "ERROR"})
            continue
        result = scan_path(path)
        fired = sorted({f.rule_id.value for f in result.findings})
        entry = {
            "id": row["id"],
            "label": row["label"],
            "tier": row.get("tier", "core"),
            "source": row.get("source"),
            "expected_verdict": row["expected_verdict"],
            "actual_verdict": result.verdict.value,
            "expected_rules": row.get("expected_rules", []),
            "fired_rules": fired,
            "finding_count": len(result.findings),
        }
        details.append(entry)

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
            if result.verdict is Verdict.WARN:
                warn_on_safe += 1

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
        "warn_on_safe": warn_on_safe,
        "warn_rate_on_safe": (warn_on_safe / safe_total) if safe_total else 0.0,
    }
    return {"metrics": metrics, "details": details}


def gates_core(m: dict) -> list[str]:
    fails = []
    if m["unsafe_recall"] < MIN_UNSAFE_RECALL:
        fails.append(f"core unsafe_recall {m['unsafe_recall']:.3f} < {MIN_UNSAFE_RECALL}")
    if m["rule_recall"] < MIN_RULE_RECALL:
        fails.append(f"core rule_recall {m['rule_recall']:.3f} < {MIN_RULE_RECALL}")
    if m["safe_fpr"] > MAX_SAFE_FPR:
        fails.append(f"core safe_fpr {m['safe_fpr']:.3f} > {MAX_SAFE_FPR}")
    return fails


def gates_adv(m: dict) -> list[str]:
    fails = []
    if m["unsafe_recall"] < MIN_ADV_ATTACK_RECALL:
        fails.append(
            f"adversarial attack_recall {m['unsafe_recall']:.3f} < {MIN_ADV_ATTACK_RECALL}"
        )
    if m["safe_fpr"] > MAX_ADV_SAFE_FPR:
        fails.append(f"adversarial safe_fpr {m['safe_fpr']:.3f} > {MAX_ADV_SAFE_FPR}")
    return fails


def gates_ood(m: dict) -> list[str]:
    fails = []
    if m["safe_total"] < MIN_OOD_SAFE_COUNT:
        fails.append(
            f"ood safe_total {m['safe_total']} < {MIN_OOD_SAFE_COUNT} (corpus too small)"
        )
    if m["safe_fpr"] > MAX_OOD_SAFE_FPR:
        fails.append(f"ood safe_fpr {m['safe_fpr']:.3f} > {MAX_OOD_SAFE_FPR}")
    return fails


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="skill-guard dataset eval")
    ap.add_argument("--check", action="store_true", help="exit 1 if gates fail")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--details", action="store_true")
    ap.add_argument(
        "--suite",
        choices=["core", "adversarial", "ood", "all"],
        default="all",
    )
    args = ap.parse_args(argv)

    reports: dict = {}
    fails: list[str] = []

    if args.suite in {"core", "all"}:
        core_rows = [
            r
            for r in load_catalog(ROOT / "dataset" / "catalog.jsonl")
            if r.get("tier", "core") == "core" and r.get("label") != "borderline"
        ]
        core = evaluate(core_rows)
        reports["core"] = core
        if args.check:
            fails.extend(gates_core(core["metrics"]))

    if args.suite in {"adversarial", "all"}:
        adv_cat = ROOT / "dataset" / "adversarial_catalog.jsonl"
        if not adv_cat.is_file():
            print(f"error: missing {adv_cat}", file=sys.stderr)
            return 2
        adv = evaluate(load_catalog(adv_cat))
        reports["adversarial"] = adv
        if args.check:
            fails.extend(gates_adv(adv["metrics"]))

    if args.suite in {"ood", "all"}:
        ood_cat = ROOT / "dataset" / "ood_catalog.jsonl"
        if not ood_cat.is_file():
            print(f"error: missing {ood_cat}", file=sys.stderr)
            return 2
        ood = evaluate(load_catalog(ood_cat))
        reports["ood"] = ood
        if args.check:
            fails.extend(gates_ood(ood["metrics"]))

    if args.json:
        print(json.dumps(reports, indent=2))
    else:
        for name, rep in reports.items():
            m = rep["metrics"]
            print(f"skill-guard eval ({name})")
            if m["unsafe_total"]:
                print(
                    f"  attack/unsafe_recall: {m['unsafe_recall']:.3f} "
                    f"({m['unsafe_blocked']}/{m['unsafe_total']})"
                )
                print(
                    f"  rule_recall:          {m['rule_recall']:.3f} "
                    f"({m['rule_hits']}/{m['rule_total']})"
                )
            print(
                f"  safe_fpr (BLOCK):     {m['safe_fpr']:.3f} "
                f"({m['safe_blocked']}/{m['safe_total']} blocked)"
            )
            if m.get("warn_on_safe"):
                print(
                    f"  warn_rate on safe:    {m['warn_rate_on_safe']:.3f} "
                    f"({m['warn_on_safe']}/{m['safe_total']})  # not a hard gate"
                )
            if args.details:
                for d in rep["details"]:
                    mark = "ok"
                    if d["label"] == "unsafe" and d["actual_verdict"] != "BLOCK":
                        mark = "MISS"
                    if d["label"] == "safe" and d["actual_verdict"] == "BLOCK":
                        mark = "FP"
                    print(
                        f"  [{mark}] {d['id']}: {d['actual_verdict']} "
                        f"rules={d.get('fired_rules')}"
                    )

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
