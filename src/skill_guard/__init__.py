"""skill-guard: deterministic pre-install audit for Agent Skills."""

from skill_guard.engine import scan_path
from skill_guard.models import Finding, ScanResult, Severity, Verdict

__version__ = "0.2.0"
__all__ = [
    "Finding",
    "ScanResult",
    "Severity",
    "Verdict",
    "scan_path",
    "__version__",
]
