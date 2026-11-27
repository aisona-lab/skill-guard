"""Deterministic offline latency, accuracy, and cost benchmark.

Measures per-skill ``scan_path`` latency (p50 / p95 in ms), false-BLOCK (FP),
false-negative (FN), and per-1,000-scan cost across all evaluation suites:
  - core
  - adversarial
  - ood (73 real-world safe skills)
  - ood-unsafe (held-out attack packs)

Run:
  uv run python eval/bench_latency.py
  uv run python eval/bench_latency.py --rounds 5 --json
"""

from __future__ import annotations

import argparse
import json
import statistics
import sys
import time
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from skill_guard.engine import scan_path  # noqa: E402
from skill_guard.models import Verdict  # noqa: E402
from skill_guard.parser import load_package  # noqa: E402


def _load_catalog(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        rows.append(json.loads(line))
    return rows


def _percentile(sorted_vals: list[float], pct: float) -> float:
    """Linear-interpolated percentile on pre-sorted values."""
    if not sorted_vals:
        return 0.0
    if len(sorted_vals) == 1:
        return sorted_vals[0]
    pos = (len(sorted_vals) - 1) * (pct / 100.0)
    lo = int(pos)
    hi = min(lo + 1, len(sorted_vals) - 1)
    frac = pos - lo
    return sorted_vals[lo] * (1.0 - frac) + sorted_vals[hi] * frac


def _load_suite_rows(suite: str) -> dict[str, list[dict[str, Any]]]:
    suites: dict[str, list[dict[str, Any]]] = {}
    if suite in {"core", "all"}:
        suites["core"] = [
            r
            for r in _load_catalog(ROOT / "dataset" / "catalog.jsonl")
            if r.get("tier", "core") == "core" and r.get("label") != "borderline"
        ]
    if suite in {"adversarial", "all"}:
        suites["adversarial"] = _load_catalog(ROOT / "dataset" / "adversarial_catalog.jsonl")
    if suite in {"ood", "all"}:
        suites["ood"] = _load_catalog(ROOT / "dataset" / "ood_catalog.jsonl")
    if suite in {"ood-unsafe", "all"}:
        suites["ood-unsafe"] = _load_catalog(ROOT / "dataset" / "ood_unsafe_catalog.jsonl")
    return suites


def benchmark_suite(
    name: str,
    rows: list[dict[str, Any]],
    *,
    rounds: int,
    warmup: int,
) -> dict[str, Any]:
    paths: list[tuple[dict[str, Any], Path]] = []
    for row in rows:
        p = ROOT / "dataset" / row["path"]
        if not p.is_file() and not p.is_dir():
            raise FileNotFoundError(f"missing dataset entry for {name}: {p}")
        paths.append((row, p))

    # Warmup pass(es) outside timed measurements.
    for _ in range(warmup):
        for _, p in paths:
            scan_path(p)

    # Accuracy + package byte counts (single deterministic pass).
    safe_total = 0
    safe_blocked = 0
    warn_on_safe = 0
    unsafe_total = 0
    unsafe_blocked = 0
    total_chars = 0
    total_files = 0

    for row, p in paths:
        res = scan_path(p)
        ctx = load_package(p)
        total_chars += sum(len(f.content) for f in ctx.files)
        total_files += len(ctx.files)

        label = row["label"]
        if label == "safe":
            safe_total += 1
            if res.verdict is Verdict.BLOCK:
                safe_blocked += 1
            elif res.verdict is Verdict.WARN:
                warn_on_safe += 1
        elif label == "unsafe":
            unsafe_total += 1
            if res.verdict is Verdict.BLOCK:
                unsafe_blocked += 1

    # Latency measurements: median ms per skill across `rounds` passes.
    per_skill_samples: list[list[float]] = [[] for _ in paths]
    for _ in range(rounds):
        for idx, (_, p) in enumerate(paths):
            t0 = time.perf_counter()
            scan_path(p)
            dt_ms = (time.perf_counter() - t0) * 1000.0
            per_skill_samples[idx].append(dt_ms)

    per_skill_medians = sorted(statistics.median(samples) for samples in per_skill_samples)
    fn_count = unsafe_total - unsafe_blocked
    n = len(paths)

    return {
        "suite": name,
        "skills": n,
        "files": total_files,
        "avg_est_input_tokens": round((total_chars / 4.0) / n) if n else 0,
        "p50_ms": round(_percentile(per_skill_medians, 50.0), 3),
        "p95_ms": round(_percentile(per_skill_medians, 95.0), 3),
        "total_median_ms": round(sum(per_skill_medians), 2),
        "safe_total": safe_total,
        "fp_block": safe_blocked,
        "warn_on_safe": warn_on_safe,
        "unsafe_total": unsafe_total,
        "unsafe_blocked": unsafe_blocked,
        "fn_miss": fn_count,
        "recall": (unsafe_blocked / unsafe_total) if unsafe_total else None,
        "fpr": (safe_blocked / safe_total) if safe_total else None,
    }


def _estimate_llm_cost_per_1k(avg_input_tokens: float) -> dict[str, Any]:
    """Reference LLM-as-a-judge cost per 1,000 scans vs $0.000 offline cost.

    Uses measured corpus average (~4 chars/token) + 250 output tokens per scan:
      - Fast tier reference: $1.00 / 1M input, $5.00 / 1M output
      - Mid tier reference:  $3.00 / 1M input, $15.00 / 1M output
    """
    out_tokens = 250.0
    fast = 1000.0 * ((avg_input_tokens * 1.00 + out_tokens * 5.00) / 1_000_000.0)
    mid = 1000.0 * ((avg_input_tokens * 3.00 + out_tokens * 15.00) / 1_000_000.0)
    return {
        "skill_guard_per_1k_usd": 0.0,
        "avg_est_input_tokens": round(avg_input_tokens),
        "assumed_output_tokens": int(out_tokens),
        "llm_fast_tier_per_1k_usd": round(fast, 2),
        "llm_mid_tier_per_1k_usd": round(mid, 2),
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="skill-guard offline latency & accuracy benchmark")
    ap.add_argument(
        "--suite",
        choices=["core", "adversarial", "ood", "ood-unsafe", "all"],
        default="all",
    )
    ap.add_argument("--rounds", type=int, default=5, help="Timed passes per suite (default: 5)")
    ap.add_argument("--warmup", type=int, default=1, help="Warmup passes per suite (default: 1)")
    ap.add_argument("--json", action="store_true", help="Output JSON report")
    args = ap.parse_args(argv)

    suites = _load_suite_rows(args.suite)
    results = [
        benchmark_suite(name, rows, rounds=args.rounds, warmup=args.warmup)
        for name, rows in suites.items()
    ]

    total_skills = sum(r["skills"] for r in results)
    weighted_tokens = (
        sum(r["avg_est_input_tokens"] * r["skills"] for r in results) / total_skills
        if total_skills
        else 0.0
    )
    cost = _estimate_llm_cost_per_1k(weighted_tokens)
    payload = {
        "rounds": args.rounds,
        "warmup": args.warmup,
        "suites": results,
        "cost": cost,
    }

    if args.json:
        print(json.dumps(payload, indent=2))
        return 0

    print(f"skill-guard offline benchmark (rounds={args.rounds}, warmup={args.warmup})")
    print(
        f"{'Suite':<12} {'Skills':>6} {'p50 ms':>8} {'p95 ms':>8} "
        f"{'FP (BLOCK)':>12} {'FN (miss)':>11} {'Recall':>8}"
    )
    print("-" * 71)
    for r in results:
        fp_str = f"{r['fp_block']}/{r['safe_total']}" if r["safe_total"] else "-"
        fn_str = f"{r['fn_miss']}/{r['unsafe_total']}" if r["unsafe_total"] else "-"
        rec_str = f"{r['recall']:.3f}" if r["recall"] is not None else "-"
        print(
            f"{r['suite']:<12} {r['skills']:>6} {r['p50_ms']:>8.3f} {r['p95_ms']:>8.3f} "
            f"{fp_str:>12} {fn_str:>11} {rec_str:>8}"
        )
    print("-" * 71)
    print(
        f"Cost / 1,000 scans: skill-guard = ${cost['skill_guard_per_1k_usd']:.3f} "
        f"(vs ~${cost['llm_fast_tier_per_1k_usd']:.2f}–${cost['llm_mid_tier_per_1k_usd']:.2f} "
        f"LLM-as-a-judge reference @ ~{cost['avg_est_input_tokens']} in + "
        f"{cost['assumed_output_tokens']} out tok/skill)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
