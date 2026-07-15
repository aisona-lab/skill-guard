"""Unified sensitive-path and sink catalog.

Single source of truth for SG004 / SG010 / language detectors.
Keep patterns high-signal; document each entry's threat.
"""

from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class PathPattern:
    """A sensitive filesystem or cloud path pattern."""

    id: str
    regex: re.Pattern[str]
    title: str
    severity: str  # critical | high | medium — mapped by callers


# Paths that, when read or uploaded, indicate credential theft risk.
SENSITIVE_PATHS: list[PathPattern] = [
    PathPattern(
        "ssh_dir",
        re.compile(
            r"(?i)(\.ssh[/\\]|[/\\]\.ssh\b|id_rsa|id_ed25519|id_ecdsa|authorized_keys)"
        ),
        "SSH key material path",
        "critical",
    ),
    PathPattern(
        "aws_creds",
        re.compile(
            r"(?i)(\.aws[/\\]credentials|\.aws[/\\]config|AWS_SHARED_CREDENTIALS_FILE)"
        ),
        "AWS credentials path",
        "critical",
    ),
    PathPattern(
        "gcp_creds",
        re.compile(
            r"(?i)(\.config[/\\]gcloud|application_default_credentials|"
            r"GOOGLE_APPLICATION_CREDENTIALS)"
        ),
        "GCP credentials path",
        "critical",
    ),
    PathPattern(
        "azure_creds",
        re.compile(r"(?i)(\.azure[/\\]|AZURE_CONFIG_DIR)"),
        "Azure credentials path",
        "high",
    ),
    PathPattern(
        "kube",
        re.compile(r"(?i)(\.kube[/\\]config|KUBECONFIG)"),
        "Kubernetes config path",
        "high",
    ),
    PathPattern(
        "env_file",
        re.compile(r"(?i)(?<![A-Za-z0-9_])\.env(?:\.[A-Za-z0-9_-]+)?(?![A-Za-z0-9_])"),
        "Environment file path",
        "high",
    ),
    PathPattern(
        "gnupg",
        re.compile(r"(?i)(\.gnupg[/\\]|secring\.gpg)"),
        "GPG keyring path",
        "high",
    ),
    PathPattern(
        "docker_sock",
        re.compile(r"(?i)(/var/run/docker\.sock|docker\.sock)"),
        "Docker daemon socket",
        "critical",
    ),
    PathPattern(
        "etc_shadow",
        re.compile(r"(?i)(/etc/shadow|/etc/passwd|/etc/sudoers)"),
        "System credential file",
        "critical",
    ),
    PathPattern(
        "home_escape",
        re.compile(
            r"(?i)(\$HOME|\$\{HOME\}|%USERPROFILE%|%HOMEPATH%|Path\.home\(\)|"
            r"expanduser\(['\"]~)"
        ),
        "Home directory expansion",
        "medium",
    ),
]

CLOUD_METADATA: list[PathPattern] = [
    PathPattern(
        "imds",
        re.compile(
            r"(?i)(169\.254\.169\.254|metadata\.google\.internal|"
            r"metadata\.azure\.com|instance-data\.ec2)"
        ),
        "Cloud instance metadata endpoint",
        "critical",
    ),
]

NETWORK_SINK_HINTS = re.compile(
    r"(?i)\b("
    r"curl|wget|fetch|httpx|requests\.(get|post|put|patch)|"
    r"urllib\.request|urlopen|Invoke-WebRequest|Invoke-RestMethod|"
    r"Net\.WebClient|DownloadString|DownloadFile|"
    r"axios\.|node-fetch|got\(|http\.request|"
    r"scp|rsync|ftp|sftp"
    r")\b"
)

READ_HINTS = re.compile(
    r"(?i)\b("
    r"cat|head|tail|type|Get-Content|Get-Item|"
    r"open\(|read_text|read_bytes|readFile|readFileSync|"
    r"pathlib\.Path|Path\(|expanduser"
    r")\b"
)


def find_sensitive_paths(text: str) -> list[tuple[PathPattern, re.Match[str]]]:
    """Return all sensitive path matches in text."""
    hits: list[tuple[PathPattern, re.Match[str]]] = []
    for pp in SENSITIVE_PATHS + CLOUD_METADATA:
        for m in pp.regex.finditer(text):
            hits.append((pp, m))
    return hits


def has_network_sink(text: str) -> bool:
    return NETWORK_SINK_HINTS.search(text) is not None


def has_read_hint(text: str) -> bool:
    return READ_HINTS.search(text) is not None


def read_then_network_risk(text: str, window: int = 400) -> list[str]:
    """Heuristic: sensitive path near a network sink within *window* chars.

    Returns list of path pattern ids that look exfiltrated.
    """
    risks: list[str] = []
    for pp, m in find_sensitive_paths(text):
        start = max(0, m.start() - window)
        end = min(len(text), m.end() + window)
        chunk = text[start:end]
        if has_network_sink(chunk) or has_read_hint(chunk):
            # require either explicit read OR network when path is critical
            if has_network_sink(chunk) or (
                has_read_hint(chunk) and pp.severity in {"critical", "high"}
            ):
                risks.append(pp.id)
    # unique preserve order
    seen: set[str] = set()
    out: list[str] = []
    for r in risks:
        if r not in seen:
            seen.add(r)
            out.append(r)
    return out
