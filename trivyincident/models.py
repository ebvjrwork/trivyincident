from dataclasses import dataclass

SEVERITY_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "INFO": 1}


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
