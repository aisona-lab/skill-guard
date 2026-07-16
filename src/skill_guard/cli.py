"""CLI entrypoint.

Exit codes (CI contract):
  0 ALLOW
  1 WARN
  2 BLOCK
  3 usage / path error
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from skill_guard import __version__
from skill_guard.config import load_config
from skill_guard.engine import scan_many
from skill_guard.report import render_json_multi, render_text
from skill_guard.sarif import render_sarif_multi


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="skill-guard",
        description="Audit Agent Skills before install. Deterministic. Offline.",
    )
    p.add_argument("--version", action="version", version=f"skill-guard {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    scan = sub.add_parser("scan", help="Scan a skill directory or SKILL.md")
    scan.add_argument(
        "path",
        type=str,
        nargs="+",
        help="Path(s) to skill package(s) or SKILL.md",
    )
    out = scan.add_mutually_exclusive_group()
    out.add_argument("--json", action="store_true", help="JSON report(s) to stdout")
    out.add_argument(
        "--sarif",
        action="store_true",
        help="Single SARIF 2.1.0 document to stdout (merges multi-target scans)",
    )
    scan.add_argument(
        "--sarif-file",
        type=str,
        default=None,
        metavar="PATH",
        help="Write SARIF to PATH (one document; still prints text unless --json/--sarif)",
    )
    scan.add_argument(
        "--rules",
        type=str,
        default=None,
        help="Comma-separated rule ids to run (default: all enabled)",
    )
    scan.add_argument(
        "--fail-on",
        choices=["never", "warn", "block"],
        default=None,
        help="Override config fail-on (default: config or block)",
    )
    scan.add_argument(
        "--pack",
        choices=["default", "strict"],
        default=None,
        help="Policy pack: default (fail on BLOCK) or strict (fail on WARN+)",
    )
    scan.add_argument(
        "--config",
        type=str,
        default=None,
        help="Path to .skill-guard.yml",
    )
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    if args.cmd != "scan":
        return 3

    cfg = load_config(args.config, pack=args.pack)
    if args.fail_on:
        cfg = cfg.model_copy(update={"fail_on": args.fail_on})

    rules = [r.strip() for r in args.rules.split(",")] if args.rules else None
    paths = [Path(p) for p in args.path]
    for path in paths:
        if not path.exists():
            print(f"error: path not found: {path}", file=sys.stderr)
            return 3

    results = scan_many(paths, rules=rules, config=cfg)
    worst = max((r.exit_code for r in results), default=0)

    if args.sarif_file:
        Path(args.sarif_file).write_text(
            render_sarif_multi(results), encoding="utf-8"
        )

    if args.sarif:
        print(render_sarif_multi(results))
    elif args.json:
        print(render_json_multi(results))
    else:
        for i, result in enumerate(results):
            print(render_text(result))
            if i + 1 < len(results):
                print("---")

    return _exit_for(worst, cfg.fail_on)


def _exit_for(code: int, fail_on: str) -> int:
    if fail_on == "never":
        return 0
    if fail_on == "warn":
        return code
    return 2 if code == 2 else 0


if __name__ == "__main__":
    raise SystemExit(main())
