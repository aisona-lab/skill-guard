"""Unified sensitive-path and sink catalog.

Single source of truth for SG004 / SG010 / language detectors.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from skill_guard.models import Severity


@dataclass(frozen=True, slots=True)
class PathPattern:
    """A sensitive filesystem or cloud path pattern."""

    id: str
    regex: re.Pattern[str]
    title: str
    severity: Severity


SENSITIVE_PATHS: list[PathPattern] = [
    PathPattern(
        "ssh_dir",
        re.compile(
            r"(?i)(\.ssh[/\\]|[/\\]\.ssh\b|id_rsa|id_ed25519|id_ecdsa|authorized_keys)"
        ),
        "SSH key material path",
        Severity.CRITICAL,
    ),
    PathPattern(
        "aws_creds",
        re.compile(
            r"(?i)(\.aws[/\\]credentials|\.aws[/\\]config|AWS_SHARED_CREDENTIALS_FILE)"
        ),
        "AWS credentials path",
        Severity.CRITICAL,
    ),
    PathPattern(
        "gcp_creds",
        re.compile(
            r"(?i)(\.config[/\\]gcloud|application_default_credentials|"
            r"GOOGLE_APPLICATION_CREDENTIALS)"
        ),
        "GCP credentials path",
        Severity.CRITICAL,
    ),
    PathPattern(
        "azure_creds",
        re.compile(r"(?i)(\.azure[/\\]|AZURE_CONFIG_DIR)"),
        "Azure credentials path",
        Severity.HIGH,
    ),
    PathPattern(
        "kube",
        re.compile(r"(?i)(\.kube[/\\]config|KUBECONFIG)"),
        "Kubernetes config path",
        Severity.HIGH,
    ),
    PathPattern(
        "env_file",
        re.compile(r"(?i)(?<![A-Za-z0-9_])\.env(?:\.[A-Za-z0-9_-]+)?(?![A-Za-z0-9_])"),
        "Environment file path",
        Severity.HIGH,
    ),
    PathPattern(
        "gnupg",
        re.compile(r"(?i)(\.gnupg[/\\]|secring\.gpg)"),
        "GPG keyring path",
        Severity.HIGH,
    ),
    PathPattern(
        "docker_sock",
        re.compile(r"(?i)(/var/run/docker\.sock|docker\.sock)"),
        "Docker daemon socket",
        Severity.CRITICAL,
    ),
    PathPattern(
        "etc_shadow",
        re.compile(r"(?i)(/etc/shadow|/etc/passwd|/etc/sudoers)"),
        "System credential file",
        Severity.CRITICAL,
    ),
    PathPattern(
        "home_escape",
        re.compile(
            r"(?i)(\$HOME|\$\{HOME\}|%USERPROFILE%|%HOMEPATH%|Path\.home\(\)|"
            r"expanduser\(['\"]~)"
        ),
        "Home directory expansion",
        Severity.MEDIUM,
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
        Severity.CRITICAL,
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
    hits: list[tuple[PathPattern, re.Match[str]]] = []
    for pp in SENSITIVE_PATHS + CLOUD_METADATA:
        for m in pp.regex.finditer(text):
            hits.append((pp, m))
    return hits


def has_network_sink(text: str) -> bool:
    return NETWORK_SINK_HINTS.search(text) is not None


def has_read_hint(text: str) -> bool:
    return READ_HINTS.search(text) is not None


_EXFIL_CONTEXT = re.compile(
    r"(?i)("
    r"curl\s+[^\n]{0,40}(-d|--data|-F|--form)|"
    r"requests\.(post|put)|httpx\.(post|put)|"
    r"fetch\([^\)]*method\s*:\s*['\"]POST|"
    r"base64\s+.*\|.*curl|"
    r"cat\s+[^\n]{0,20}\.env|"
    r"readFileSync\([^\)]*\.env|"
    r"open\([^\)]*\.env"
    r")"
)


def read_then_network_risk(text: str, window: int = 400) -> list[str]:
    """Sensitive path near read+exfil context within *window* chars.

    Bare co-occurrence of ``.env`` and ``curl`` in deploy docs is not enough;
    require upload/post/read-of-env signals to avoid FPs on legitimate tooling.
    """
    risks: list[str] = []
    for pp, m in find_sensitive_paths(text):
        start = max(0, m.start() - window)
        end = min(len(text), m.end() + window)
        chunk = text[start:end]
        if pp.id == "env_file":
            # env files are common in deploy skills; only flag strong exfil shape
            if _EXFIL_CONTEXT.search(chunk) and has_network_sink(chunk):
                risks.append(pp.id)
            continue
        if has_network_sink(chunk) and (
            has_read_hint(chunk) or pp.severity is Severity.CRITICAL
        ):
            risks.append(pp.id)
        elif has_read_hint(chunk) and pp.severity is Severity.CRITICAL and has_network_sink(
            chunk
        ):
            risks.append(pp.id)
    seen: set[str] = set()
    out: list[str] = []
    for r in risks:
        if r not in seen:
            seen.add(r)
            out.append(r)
    return out
