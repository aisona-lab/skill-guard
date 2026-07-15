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
from skill_guard.engine import scan_path
from skill_guard.report import render_json, render_text


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="skill-guard",
        description="Audit Agent Skills before install. Deterministic. Offline.",
    )
    p.add_argument("--version", action="version", version=f"skill-guard {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    scan = sub.add_parser("scan", help="Scan a skill directory or SKILL.md")
    scan.add_argument("path", type=str, help="Path to skill package or SKILL.md")
    scan.add_argument(
        "--json",
        action="store_true",
        help="Emit machine-readable JSON report",
    )
    scan.add_argument(
        "--rules",
        type=str,
        default=None,
        help="Comma-separated rule ids to run (default: all)",
    )
    scan.add_argument(
        "--fail-on",
        choices=["never", "warn", "block"],
        default="block",
        help="Minimum verdict that yields non-zero exit (default: block)",
    )
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    if args.cmd == "scan":
        path = Path(args.path)
        if not path.exists():
            print(f"error: path not found: {path}", file=sys.stderr)
            return 3
        rules = [r.strip() for r in args.rules.split(",")] if args.rules else None
        result = scan_path(path, rules=rules)
        print(render_json(result) if args.json else render_text(result))
        return _exit_for(result.exit_code, args.fail_on)

    return 3


def _exit_for(code: int, fail_on: str) -> int:
    """Map scan severity to process exit based on --fail-on."""
    if fail_on == "never":
        return 0
    if fail_on == "warn":
        return code  # WARN=1 and BLOCK=2 both fail
    # fail_on == block: only BLOCK is non-zero
    return 2 if code == 2 else 0


if __name__ == "__main__":
    raise SystemExit(main())
