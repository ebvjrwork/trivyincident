import os
import re
from datetime import datetime, timezone
from typing import List, Optional, Set, Tuple

from .models import Finding, RunInfo

MALICIOUS_WORKFLOW_SHAS: Set[str] = set()
MALICIOUS_BINARY_SHA256: Set[str] = set()
NETWORK_IOCS: Set[str] = set()

ACTION_REF_RE = re.compile(r"aquasecurity/(trivy-action|setup-trivy)@([A-Za-z0-9._/-]+)", re.IGNORECASE)
ACTION_SHA_RE = re.compile(r"\b([0-9a-f]{40})\b", re.IGNORECASE)
SHA256_RE = re.compile(r"\b([0-9a-f]{64})\b", re.IGNORECASE)
TRIVY_WORD_RE = re.compile(r"\btrivy\b", re.IGNORECASE)
APT_TRIVY_RE = re.compile(r"\bapt(?:-get)?\s+.*\binstall\b.*\btrivy\b", re.IGNORECASE)
TRIVY_VERSION_RE = re.compile(r"\b(?:trivy\s+)?v?(0\.\d+\.\d+)\b", re.IGNORECASE)
DOWNLOAD_RE = re.compile(r"\b(curl|wget)\b", re.IGNORECASE)
CONTAINER_RE = re.compile(r"\bdocker\s+run\b.*\b(trivy|aquasec/trivy)\b", re.IGNORECASE)
DOWNLOAD_ACTION_RE = re.compile(
    r"Download action repository '([^/\s]+/[^@\s]+)@([^']+)' \(SHA:([0-9a-f]{40})\)",
    re.IGNORECASE,
)
LOG_TIMESTAMP_RE = re.compile(r"\b(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2}))\b")
COMPLETE_JOB_NAME_RE = re.compile(r"Complete job name:\s*(.+)", re.IGNORECASE)
LOG_SECTION_HEADER_RE = re.compile(r"^=====\s+\d+_(.+?)\.txt\s+=====$")
ANSI_ESCAPE_RE = re.compile(r"\x1B\[[0-?]*[ -/]*[@-~]")
APT_TRIVY_VERSION_PATTERNS = [
    re.compile(r"trivy_(0\.\d+\.\d+)_", re.IGNORECASE),
    re.compile(r"\bUnpacking\s+trivy\s+\((0\.\d+\.\d+)\)", re.IGNORECASE),
    re.compile(r"\bSetting\s+up\s+trivy\s+\((0\.\d+\.\d+)\)", re.IGNORECASE),
    re.compile(r"\bGet:\d+\s+\S+\s+\S+\s+\S+\s+trivy\s+\S+\s+(0\.\d+\.\d+)\b", re.IGNORECASE),
    re.compile(r"\btrivy\s*=\s*(0\.\d+\.\d+)\b", re.IGNORECASE),
]


def set_indicator_sets(workflow: Set[str], binary: Set[str], network: Set[str]) -> None:
    global MALICIOUS_WORKFLOW_SHAS, MALICIOUS_BINARY_SHA256, NETWORK_IOCS
    MALICIOUS_WORKFLOW_SHAS = set(workflow)
    MALICIOUS_BINARY_SHA256 = set(binary)
    NETWORK_IOCS = set(network)


def classify_usage(lines: List[str]) -> str:
    has_apt = any(APT_TRIVY_RE.search(line) for line in lines)
    has_action = any(ACTION_REF_RE.search(line) for line in lines)
    has_download = any(DOWNLOAD_RE.search(line) for line in lines) and any(TRIVY_WORD_RE.search(line) for line in lines)
    has_container = any(CONTAINER_RE.search(line) for line in lines)
    if has_apt:
        return "apt"
    if has_action:
        return "action"
    if has_download:
        return "binary-download"
    if has_container:
        return "container"
    return "unknown"


def extract_apt_trivy_versions(lines: List[str]) -> Set[str]:
    versions: Set[str] = set()
    for line in lines:
        for pattern in APT_TRIVY_VERSION_PATTERNS:
            for match in pattern.finditer(line):
                versions.add(match.group(1))
    return versions


def _normalize_timestamp(raw: str) -> Optional[str]:
    normalized = raw
    if normalized.endswith("Z"):
        normalized = normalized[:-1] + "+00:00"
    elif re.fullmatch(r".*[+-]\d{4}$", normalized):
        normalized = normalized[:-5] + normalized[-5:-2] + ":" + normalized[-2:]
    try:
        dt = datetime.fromisoformat(normalized)
        return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    except Exception:
        return None


def extract_first_log_timestamp(lines: List[str]) -> str:
    for line in lines:
        match = LOG_TIMESTAMP_RE.search(line)
        if not match:
            continue
        normalized = _normalize_timestamp(match.group(1))
        if normalized:
            return normalized
    return ""


def extract_first_log_timestamp_from_file(log_path: str) -> str:
    try:
        with open(log_path, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                match = LOG_TIMESTAMP_RE.search(line)
                if not match:
                    continue
                normalized = _normalize_timestamp(match.group(1))
                if normalized:
                    return normalized
    except OSError:
        return ""
    return ""


def extract_workflow_name_from_file(log_path: str) -> str:
    section_fallback = ""
    try:
        with open(log_path, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                raw = line.strip().lstrip("\ufeff")
                match = COMPLETE_JOB_NAME_RE.search(raw)
                if match:
                    name = match.group(1).strip()
                    if name:
                        return name
                if not section_fallback:
                    section_match = LOG_SECTION_HEADER_RE.match(raw)
                    if section_match:
                        candidate = section_match.group(1).strip()
                        if candidate:
                            section_fallback = candidate
    except OSError:
        return ""
    return section_fallback


def parse_log_for_finding(run: RunInfo, log_path: str) -> Optional[Finding]:
    with open(log_path, "r", encoding="utf-8", errors="replace") as f:
        lines = f.readlines()

    run_time_utc_value = run.created_at or extract_first_log_timestamp(lines)

    lower_lines = [line.lower() for line in lines]
    trivy_lines_idx = [i for i, line in enumerate(lower_lines) if "trivy" in line]
    if not trivy_lines_idx:
        return None

    action_refs: List[str] = []
    resolved_shas: Set[str] = set()
    versions: Set[str] = set()
    hash_seen: Set[str] = set()
    ioc_hits: Set[str] = set()
    apt_0694 = False
    trivy_action_downloads: List[Tuple[str, str, str]] = []

    for line in lines:
        action_download_match = DOWNLOAD_ACTION_RE.search(line)
        if action_download_match:
            action_repo = action_download_match.group(1).lower()
            action_ref_value = action_download_match.group(2)
            action_sha_value = action_download_match.group(3).lower()
            if action_repo in {"aquasecurity/setup-trivy", "aquasecurity/trivy-action"}:
                trivy_action_downloads.append((action_repo, action_ref_value, action_sha_value))
                if action_sha_value in MALICIOUS_WORKFLOW_SHAS:
                    ioc_hits.add(f"workflow-sha:{action_repo}:{action_sha_value}")

        for m in ACTION_REF_RE.finditer(line):
            action_refs.append(f"aquasecurity/{m.group(1)}@{m.group(2)}")
        for m in ACTION_SHA_RE.finditer(line):
            sha = m.group(1).lower()
            if sha in MALICIOUS_WORKFLOW_SHAS:
                ioc_hits.add(f"workflow-sha:unknown:{sha}")
        for m in SHA256_RE.finditer(line):
            sha256 = m.group(1).lower()
            hash_seen.add(sha256)
            if sha256 in MALICIOUS_BINARY_SHA256:
                ioc_hits.add(f"binary-sha256:{sha256}")
        for ioc in NETWORK_IOCS:
            if ioc in line.lower():
                ioc_hits.add(f"network:{ioc}")
        if TRIVY_WORD_RE.search(line):
            for vm in TRIVY_VERSION_RE.finditer(line):
                versions.add(vm.group(1))
        if APT_TRIVY_RE.search(line):
            if "0.69.4" in line:
                apt_0694 = True
            if re.search(r"\btrivy\s*=\s*0\.69\.4\b", line, re.IGNORECASE):
                apt_0694 = True

    usage_type = classify_usage(lines)

    if usage_type == "apt":
        apt_versions = extract_apt_trivy_versions(lines)
        if apt_versions:
            versions = apt_versions
        if "0.69.4" in versions:
            apt_0694 = True
    elif "0.69.4" in versions and any(APT_TRIVY_RE.search(line) for line in lines):
        apt_0694 = True

    if usage_type == "action" and trivy_action_downloads:
        dedup_downloads: List[Tuple[str, str, str]] = []
        seen_downloads: Set[Tuple[str, str, str]] = set()
        for item in trivy_action_downloads:
            if item in seen_downloads:
                continue
            seen_downloads.add(item)
            dedup_downloads.append(item)
        action_refs = [f"{repo}@{ref}" for repo, ref, _ in dedup_downloads]
        resolved_shas = {sha for _, _, sha in dedup_downloads}

    action_ref_risky = False
    action_ref_risk_reasons: List[str] = []
    action_ref_baseline_reasons: List[str] = []
    for ref in action_refs:
        if "@" not in ref:
            continue
        repo, tail = ref.rsplit("@", 1)
        repo = repo.lower()
        tail = tail.lower()
        if re.fullmatch(r"[0-9a-f]{40}", tail, re.IGNORECASE):
            in_db = tail in MALICIOUS_WORKFLOW_SHAS
            status = "sha-in-db" if in_db else "sha-not-in-db"
            action_ref_baseline_reasons.append(f"{repo}@{tail[:12]}({status})")
            continue
        if repo.endswith("/trivy-action"):
            if tail != "0.35.0":
                action_ref_risky = True
                action_ref_risk_reasons.append(f"{repo}@{tail}(version-tag)")
                break
            action_ref_baseline_reasons.append(f"{repo}@{tail}(safe-tag)")
        elif repo.endswith("/setup-trivy"):
            action_ref_risky = True
            action_ref_risk_reasons.append(f"{repo}@{tail}(version-tag)")
            break
        else:
            action_ref_risky = True
            action_ref_risk_reasons.append(f"{repo}@{tail}(version-tag)")
            break

    severity = "MEDIUM"
    severity_trigger = "baseline"
    if ioc_hits:
        severity = "CRITICAL"
        severity_trigger = "ioc-hit"
    elif apt_0694 or (usage_type == "action" and action_ref_risky):
        severity = "HIGH"
        if apt_0694 and usage_type == "action" and action_ref_risky:
            risk_detail = ",".join(action_ref_risk_reasons[:2]) if action_ref_risk_reasons else "unknown-action-ref"
            severity_trigger = f"apt-0.69.4+action-ref-risk:{risk_detail}"
        elif apt_0694:
            severity_trigger = "apt-0.69.4"
        else:
            risk_detail = ",".join(action_ref_risk_reasons[:2]) if action_ref_risk_reasons else "unknown-action-ref"
            severity_trigger = f"action-ref-risk:{risk_detail}"
    elif usage_type == "action" and action_ref_baseline_reasons:
        baseline_detail = ",".join(action_ref_baseline_reasons[:2])
        severity_trigger = f"baseline:{baseline_detail}"

    evidence_indices: Set[int] = set()

    def collect_indices(predicate) -> None:
        for i, line in enumerate(lines):
            if predicate(line):
                evidence_indices.add(i)

    if ioc_hits:
        for token in ioc_hits:
            if token.startswith("workflow-sha:"):
                sha = token.rsplit(":", 1)[-1]
                collect_indices(lambda line, s=sha: s in line.lower())
            elif token.startswith("binary-sha256:"):
                digest = token.split(":", 1)[1]
                collect_indices(lambda line, d=digest: d in line.lower())
            elif token.startswith("network:"):
                marker = token.split(":", 1)[1]
                collect_indices(lambda line, m=marker: m in line.lower())

    if usage_type == "action":
        collect_indices(
            lambda line: (
                (m := DOWNLOAD_ACTION_RE.search(line)) is not None
                and m.group(1).lower() in {"aquasecurity/setup-trivy", "aquasecurity/trivy-action"}
            )
        )
        collect_indices(lambda line: ACTION_REF_RE.search(line) is not None)
    elif usage_type == "apt":
        apt_patterns = [
            APT_TRIVY_RE,
            re.compile(r"\b(Unpacking|Setting up)\s+trivy\b", re.IGNORECASE),
            re.compile(r"\bGet:\d+\s+\S+\s+\S+\s+\S+\s+trivy\b", re.IGNORECASE),
            re.compile(r"\btrivy_[0-9]", re.IGNORECASE),
            re.compile(r"\btrivy\s*=\s*0\.\d+\.\d+\b", re.IGNORECASE),
        ]
        for pattern in apt_patterns:
            collect_indices(lambda line, p=pattern: p.search(line) is not None)
    elif usage_type == "binary-download":
        collect_indices(lambda line: DOWNLOAD_RE.search(line) is not None and TRIVY_WORD_RE.search(line) is not None)
    elif usage_type == "container":
        collect_indices(lambda line: CONTAINER_RE.search(line) is not None)

    if versions:
        collect_indices(lambda line: any(v in line for v in versions))

    if not evidence_indices:
        evidence_indices.add(trivy_lines_idx[0])

    snippet_lines: List[str] = []
    seen_snippet_lines: Set[str] = set()
    for index in sorted(evidence_indices):
        cleaned = lines[index].strip()
        cleaned = ANSI_ESCAPE_RE.sub("", cleaned)
        cleaned = re.sub(r"\s+", " ", cleaned)
        if not cleaned or cleaned in seen_snippet_lines:
            continue
        seen_snippet_lines.add(cleaned)
        snippet_lines.append(cleaned)

    snippet = " || ".join(snippet_lines)
    if len(snippet) > 3000:
        snippet = snippet[:2997] + "..."

    resolved_sha = ",".join(sorted(resolved_shas)[:3])
    action_ref_value = ",".join(sorted(set(action_refs))[:3])
    version_value = ",".join(sorted(versions))
    hash_value = ",".join(sorted(hash_seen)[:3])
    ioc_value = ",".join(sorted(ioc_hits)) if ioc_hits else ""

    details_parts: List[str] = []
    if usage_type == "action" and trivy_action_downloads:
        for repo, ref, sha in trivy_action_downloads:
            details_parts.append(f"{repo}@{ref} -> {sha}")
    elif usage_type == "apt":
        if version_value:
            details_parts.append(f"apt install trivy - downloaded {version_value}")
        else:
            details_parts.append("apt install trivy")
    if version_value and usage_type == "action":
        details_parts.append(f"trivy versions seen: {version_value}")
    trivy_details_value = " ; ".join(dict.fromkeys(details_parts))

    return Finding(
        repository=run.repo,
        run_id=run.run_id,
        run_time_utc=run_time_utc_value,
        workflow=run.workflow_name,
        trivy_detected="yes",
        usage_type=usage_type,
        action_ref=action_ref_value,
        resolved_sha=resolved_sha,
        version=version_value,
        hash_digest_seen=hash_value,
        ioc_match=ioc_value,
        apt_0694_flag="yes" if apt_0694 else "no",
        severity=severity,
        severity_trigger=severity_trigger,
        log_path=log_path,
        evidence_snippet=snippet,
        trivy_details=trivy_details_value,
    )
