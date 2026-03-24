from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Dict, Tuple

SEVERITY_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "INFO": 1}

EXPOSURE_WINDOWS: Dict[str, Tuple[datetime, datetime]] = {
    "trivy": (
        datetime(2026, 3, 19, 18, 22, tzinfo=timezone.utc),
        datetime(2026, 3, 19, 21, 42, tzinfo=timezone.utc),
    ),
    "trivy-action": (
        datetime(2026, 3, 19, 17, 43, tzinfo=timezone.utc),
        datetime(2026, 3, 20, 5, 40, tzinfo=timezone.utc),
    ),
    "setup-trivy": (
        datetime(2026, 3, 19, 17, 43, tzinfo=timezone.utc),
        datetime(2026, 3, 19, 21, 44, tzinfo=timezone.utc),
    ),
}


@dataclass
class RepoInfo:
    name: str
    full_name: str


@dataclass
class RunInfo:
    repo: str
    run_id: int
    run_number: int
    created_at: str
    workflow_name: str
    conclusion: str
    status: str


@dataclass
class Finding:
    repository: str
    run_id: int
    run_time_utc: str
    workflow: str
    trivy_detected: str
    usage_type: str
    action_ref: str
    resolved_sha: str
    version: str
    hash_digest_seen: str
    ioc_match: str
    apt_0694_flag: str
    severity: str
    severity_trigger: str
    log_path: str
    evidence_snippet: str
    trivy_details: str
