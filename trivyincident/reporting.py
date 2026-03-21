import html
import os
import re
from datetime import datetime, timezone
from typing import Dict, List, Set, Tuple

from .models import Finding, RunInfo, SEVERITY_RANK


def escape_md(value: str) -> str:
    text = value.replace("\n", " ").strip()
    text = text.replace("|", "\\|")
    return text


def repo_url(repo: str) -> str:
    return f"https://github.com/{repo}"


def run_url(repo: str, run_id: int) -> str:
    return f"https://github.com/{repo}/actions/runs/{run_id}"


def github_commit_url(action_repo: str, sha: str) -> str:
    return f"https://github.com/{action_repo}/commit/{sha}"


def red_md(value: str) -> str:
    if not value:
        return ""
    return f"<span style=\"color:red\">{escape_md(value)}</span>"


def _parse_utc_iso(value: str) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)
    except Exception:
        return None


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


def _is_sha_ref(ref_value: str) -> bool:
    if "@" not in ref_value:
        return False
    tail = ref_value.split("@", 1)[1].strip()
    return bool(re.fullmatch(r"[0-9a-f]{40}", tail, re.IGNORECASE))


def finding_exposure_match(finding: Finding) -> bool:
    run_dt = _parse_utc_iso(finding.run_time_utc)
    if run_dt is None:
        return False

    usage = (finding.usage_type or "").lower()
    refs = [x.strip().lower() for x in finding.action_ref.split(",") if x.strip()]
    versions = [x.strip() for x in finding.version.split(",") if x.strip()]
    detail_text = (finding.trivy_details or "").lower()

    component: str | None = None
    if usage == "action":
        for ref in refs:
            if ref.startswith("aquasecurity/trivy-action@"):
                if ref.endswith("@0.35.0") or _is_sha_ref(ref):
                    continue
                component = "trivy-action"
                break
            if ref.startswith("aquasecurity/setup-trivy@"):
                if _is_sha_ref(ref):
                    continue
                component = "setup-trivy"
                break
    else:
        has_0694 = finding.apt_0694_flag == "yes" or any(v == "0.69.4" for v in versions) or "0.69.4" in detail_text
        if has_0694:
            component = "trivy"

    if not component:
        return False
    start_dt, end_dt = EXPOSURE_WINDOWS[component]
    return start_dt <= run_dt <= end_dt


def maybe_red_md(value: str, should_highlight: bool) -> str:
    return red_md(value) if should_highlight and value else value


def maybe_red_html(value: str, should_highlight: bool) -> str:
    escaped = html.escape(value)
    return f'<span class="dt-red">{escaped}</span>' if should_highlight and value else escaped


def format_trivy_details_markdown(finding: Finding) -> str:
    if finding.usage_type == "action" and finding.action_ref:
        parts: List[str] = []
        refs = [x.strip() for x in finding.action_ref.split(",") if x.strip()]
        resolved = [x.strip() for x in finding.resolved_sha.split(",") if x.strip()]
        detail_map: Dict[str, str] = {}
        for chunk in finding.trivy_details.split(" ; "):
            if " -> " not in chunk:
                continue
            left, right = chunk.split(" -> ", 1)
            left = left.strip()
            right = right.strip().lower()
            if not left or not re.fullmatch(r"[0-9a-f]{40}", right, re.IGNORECASE):
                continue
            detail_map[left] = right
        for ref in refs:
            action_repo, action_version = ref.split("@", 1)
            ref_link = f"[{ref}](https://github.com/{action_repo}/tree/{action_version})"
            sha_match = detail_map.get(ref, "")
            if not sha_match:
                sha_match = next((s for s in resolved if len(s) == 40 and s in finding.trivy_details), "")
            if not sha_match and len(resolved) == 1:
                sha_match = resolved[0]
            if sha_match:
                sha_short = sha_match[:12]
                sha_link = f"[{sha_short}]({github_commit_url(action_repo, sha_match)})"
                parts.append(f"{ref_link} @ {sha_link}")
            else:
                parts.append(ref_link)
        if finding.version:
            parts.append(f"version: {finding.version}")
        return "<br>".join(parts)

    if finding.usage_type == "apt":
        apt_text = f"apt install trivy - downloaded {finding.version}" if finding.version else "apt install trivy"
        return apt_text

    return escape_md(finding.trivy_details or finding.version or "")


def format_trivy_details_html(finding: Finding) -> str:
    if finding.usage_type == "action" and finding.action_ref:
        parts: List[str] = []
        refs = [x.strip() for x in finding.action_ref.split(",") if x.strip()]
        resolved = [x.strip() for x in finding.resolved_sha.split(",") if x.strip()]
        detail_map: Dict[str, str] = {}
        for chunk in finding.trivy_details.split(" ; "):
            if " -> " not in chunk:
                continue
            left, right = chunk.split(" -> ", 1)
            left = left.strip()
            right = right.strip().lower()
            if not left or not re.fullmatch(r"[0-9a-f]{40}", right, re.IGNORECASE):
                continue
            detail_map[left] = right
        for ref in refs:
            action_repo, action_version = ref.split("@", 1)
            ref_link = (
                f'<a href="https://github.com/{html.escape(action_repo)}/tree/{html.escape(action_version)}">'
                f"{html.escape(ref)}</a>"
            )
            sha_match = detail_map.get(ref, "")
            if not sha_match:
                sha_match = next((s for s in resolved if len(s) == 40 and s in finding.trivy_details), "")
            if not sha_match and len(resolved) == 1:
                sha_match = resolved[0]
            if sha_match:
                sha_short = sha_match[:12]
                sha_link = (
                    f'<a href="{html.escape(github_commit_url(action_repo, sha_match))}">{html.escape(sha_short)}</a>'
                )
                parts.append(f"{ref_link} @ {sha_link}")
            else:
                parts.append(ref_link)
        if finding.version:
            parts.append(f"version: {html.escape(finding.version)}")
        return "<br>".join(parts)

    if finding.usage_type == "apt":
        apt_text = f"apt install trivy - downloaded {finding.version}" if finding.version else "apt install trivy"
        return html.escape(apt_text)

    return html.escape(finding.trivy_details or finding.version or "")


def write_results_md(
    output_path: str,
    org: str,
    start_iso: str,
    end_iso: str,
    repos_scanned: int,
    total_runs: int,
    downloaded: int,
    skipped_existing: int,
    failed: List[Dict[str, str]],
    findings: List[Finding],
    all_runs: List[RunInfo],
) -> None:
    findings_sorted = sorted(findings, key=lambda f: (-SEVERITY_RANK[f.severity], f.repository, f.run_id))
    findings_by_run: Dict[Tuple[str, int], Finding] = {(f.repository, f.run_id): f for f in findings_sorted}
    failed_runs: Set[Tuple[str, int]] = {(item["repo"], int(item["run_id"])) for item in failed}
    daily: Dict[str, Dict[str, int]] = {}
    for item in findings_sorted:
        day = item.run_time_utc[:10] if item.run_time_utc else "unknown"
        if day not in daily:
            daily[day] = {"total": 0, "action": 0, "apt": 0, "high": 0, "critical": 0}
        daily[day]["total"] += 1
        if item.usage_type == "action":
            daily[day]["action"] += 1
        if item.usage_type == "apt":
            daily[day]["apt"] += 1
        if item.severity == "HIGH":
            daily[day]["high"] += 1
        if item.severity == "CRITICAL":
            daily[day]["critical"] += 1

    with open(output_path, "w", encoding="utf-8") as f:
        f.write("# trivyincident Scan Results\n\n")
        f.write(f"- Organization: {org}\n")
        f.write(f"- Window (UTC): {start_iso} to {end_iso}\n")
        f.write(f"- Repositories scanned: {repos_scanned}\n")
        f.write(f"- Runs in window: {total_runs}\n")
        f.write(f"- Logs downloaded (new): {downloaded}\n")
        f.write(f"- Logs reused (already existed): {skipped_existing}\n")
        f.write(f"- Log download failures: {len(failed)}\n")
        f.write("- IOC sources: https://socket.dev/supply-chain-attacks/trivy-github-actions-compromise, https://www.wiz.io/blog/trivy-compromised-teampcp-supply-chain-attack\n\n")

        f.write("## Daily Summary\n\n")
        f.write("| Date (UTC) | Trivy Findings | GitHub Actions Usage | APT Usage | HIGH | CRITICAL |\n")
        f.write("| --- | --- | --- | --- | --- | --- |\n")
        for day in sorted(daily.keys()):
            entry = daily[day]
            f.write(
                f"| {day} | {entry['total']} | {entry['action']} | {entry['apt']} | {entry['high']} | {entry['critical']} |\n"
            )
        f.write("\n")

        headers = [
            "Date (UTC)",
            "Repository",
            "Run",
            "Run Time (UTC)",
            "Workflow",
            "Usage Type",
            "Trivy Details (Version + SHA)",
            "IOC Match",
            "Severity",
            "Severity Trigger",
            "Log Path",
            "Evidence Snippet",
        ]
        f.write("## Findings\n\n")
        f.write("| " + " | ".join(headers) + " |\n")
        f.write("| " + " | ".join(["---"] * len(headers)) + " |\n")
        for finding in findings_sorted:
            repo_link = f"[{finding.repository}]({repo_url(finding.repository)})"
            run_link = f"[{finding.run_id}]({run_url(finding.repository, finding.run_id)})"
            log_link = f"[{finding.log_path}]({finding.log_path})"
            matched_window = finding_exposure_match(finding)
            row = [
                maybe_red_md(finding.run_time_utc[:10] if finding.run_time_utc else "", matched_window),
                repo_link,
                run_link,
                maybe_red_md(finding.run_time_utc, matched_window),
                finding.workflow,
                finding.usage_type,
                format_trivy_details_markdown(finding),
                finding.ioc_match,
                finding.severity,
                finding.severity_trigger,
                log_link,
                finding.evidence_snippet,
            ]
            f.write("| " + " | ".join(escape_md(x) for x in row) + " |\n")

        f.write("\n## All Scanned Runs\n\n")
        f.write("| Date (UTC) | Repository | Run | Workflow | Status | Conclusion | Log Collected | Trivy Detected | Severity |\n")
        f.write("| --- | --- | --- | --- | --- | --- | --- | --- | --- |\n")
        for run in sorted(all_runs, key=lambda r: (r.created_at, r.repo, r.run_id)):
            key = (run.repo, run.run_id)
            finding = findings_by_run.get(key)
            matched_window = finding_exposure_match(finding) if finding else False
            row = [
                maybe_red_md(run.created_at[:10] if run.created_at else "", matched_window),
                f"[{run.repo}]({repo_url(run.repo)})",
                f"[{run.run_id}]({run_url(run.repo, run.run_id)})",
                run.workflow_name,
                run.status,
                run.conclusion,
                "yes" if key not in failed_runs else "no",
                "yes" if finding else "no",
                finding.severity if finding else "",
            ]
            f.write("| " + " | ".join(escape_md(x) for x in row) + " |\n")

        flagged = [x for x in findings_sorted if x.severity in {"CRITICAL", "HIGH"}]
        f.write("\n## Flagged Items\n\n")
        if flagged:
            for item in flagged:
                f.write(f"- {item.severity} {item.repository} run {item.run_id} ({item.usage_type}) {item.log_path}\n")
        else:
            f.write("- None\n")


def write_results_html(
    output_path: str,
    org: str,
    start_iso: str,
    end_iso: str,
    repos_scanned: int,
    total_runs: int,
    downloaded: int,
    skipped_existing: int,
    failed: List[Dict[str, str]],
    findings: List[Finding],
    all_runs: List[RunInfo],
) -> None:
    findings_sorted = sorted(findings, key=lambda f: (-SEVERITY_RANK[f.severity], f.repository, f.run_id))
    findings_by_run: Dict[Tuple[str, int], Finding] = {(f.repository, f.run_id): f for f in findings_sorted}
    failed_runs: Set[Tuple[str, int]] = {(item["repo"], int(item["run_id"])) for item in failed}

    daily: Dict[str, Dict[str, int]] = {}
    for item in findings_sorted:
        day = item.run_time_utc[:10] if item.run_time_utc else "unknown"
        if day not in daily:
            daily[day] = {"total": 0, "action": 0, "apt": 0, "high": 0, "critical": 0}
        daily[day]["total"] += 1
        if item.usage_type == "action":
            daily[day]["action"] += 1
        if item.usage_type == "apt":
            daily[day]["apt"] += 1
        if item.severity == "HIGH":
            daily[day]["high"] += 1
        if item.severity == "CRITICAL":
            daily[day]["critical"] += 1

    flagged = [x for x in findings_sorted if x.severity in {"CRITICAL", "HIGH"}]

    def td(value: str) -> str:
        return f"<td>{value}</td>"

    html_parts: List[str] = []
    html_parts.append("<!doctype html>")
    html_parts.append('<html lang="en">')
    html_parts.append("<head>")
    html_parts.append('  <meta charset="utf-8">')
    html_parts.append('  <meta name="viewport" content="width=device-width, initial-scale=1">')
    html_parts.append("  <title>trivyincident Scan Results</title>")
    html_parts.append("  <style>")
    html_parts.append("    body { font-family: Arial, sans-serif; margin: 20px; color: #111; }")
    html_parts.append("    h1, h2 { margin: 0 0 12px 0; }")
    html_parts.append("    ul { margin-top: 0; }")
    html_parts.append("    table { border-collapse: collapse; width: 100%; margin: 12px 0 24px 0; }")
    html_parts.append("    th, td { border: 1px solid #ddd; padding: 8px; font-size: 13px; vertical-align: top; }")
    html_parts.append("    th { background: #f5f5f5; text-align: left; }")
    html_parts.append("    tr:nth-child(even) { background: #fafafa; }")
    html_parts.append("    .sort-btn { border: 1px solid #ccc; background: #fff; margin-left: 4px; padding: 0 6px; font-size: 11px; line-height: 18px; cursor: pointer; }")
    html_parts.append("    .dt-red { color: #c00; font-weight: 600; }")
    html_parts.append("  </style>")
    html_parts.append("</head>")
    html_parts.append("<body>")
    html_parts.append("  <h1>trivyincident Scan Results</h1>")
    html_parts.append("  <ul>")
    html_parts.append(f"    <li>Organization: {html.escape(org)}</li>")
    html_parts.append(f"    <li>Window (UTC): {html.escape(start_iso)} to {html.escape(end_iso)}</li>")
    html_parts.append(f"    <li>Repositories scanned: {repos_scanned}</li>")
    html_parts.append(f"    <li>Runs in window: {total_runs}</li>")
    html_parts.append(f"    <li>Logs downloaded (new): {downloaded}</li>")
    html_parts.append(f"    <li>Logs reused (already existed): {skipped_existing}</li>")
    html_parts.append(f"    <li>Log download failures: {len(failed)}</li>")
    html_parts.append(
        "    <li>IOC sources: "
        '<a href="https://socket.dev/supply-chain-attacks/trivy-github-actions-compromise">socket.dev</a>, '
        '<a href="https://www.wiz.io/blog/trivy-compromised-teampcp-supply-chain-attack">wiz.io</a></li>'
    )
    html_parts.append("  </ul>")

    html_parts.append("  <h2>Daily Summary</h2>")
    html_parts.append("  <table>")
    html_parts.append("    <thead><tr><th>Date (UTC)</th><th>Trivy Findings</th><th>GitHub Actions Usage</th><th>APT Usage</th><th>HIGH</th><th>CRITICAL</th></tr></thead>")
    html_parts.append("    <tbody>")
    for day in sorted(daily.keys()):
        entry = daily[day]
        html_parts.append(
            "      <tr>"
            + td(html.escape(day))
            + td(str(entry["total"]))
            + td(str(entry["action"]))
            + td(str(entry["apt"]))
            + td(str(entry["high"]))
            + td(str(entry["critical"]))
            + "</tr>"
        )
    html_parts.append("    </tbody>")
    html_parts.append("  </table>")

    html_parts.append("  <h2>Findings</h2>")
    html_parts.append('  <table id="findings-table">')
    html_parts.append(
        "    <thead><tr>"
        "<th>Date (UTC)"
        "<button type=\"button\" class=\"sort-btn\" onclick=\"sortFindingsBy(0, true)\" title=\"Sort date ascending\">▲</button>"
        "<button type=\"button\" class=\"sort-btn\" onclick=\"sortFindingsBy(0, false)\" title=\"Sort date descending\">▼</button>"
        "</th><th>Repository</th><th>Run</th><th>Run Time (UTC)"
        "<button type=\"button\" class=\"sort-btn\" onclick=\"sortFindingsBy(3, true)\" title=\"Sort run time ascending\">▲</button>"
        "<button type=\"button\" class=\"sort-btn\" onclick=\"sortFindingsBy(3, false)\" title=\"Sort run time descending\">▼</button>"
        "</th><th>Workflow</th><th>Usage Type</th>"
        "<th>Trivy Details (Version + SHA)</th><th>IOC Match</th><th>Severity</th><th>Severity Trigger</th><th>Log Path</th><th>Evidence Snippet</th>"
        "</tr></thead>"
    )
    html_parts.append("    <tbody>")
    for finding in findings_sorted:
        repo_link = f'<a href="{html.escape(repo_url(finding.repository))}">{html.escape(finding.repository)}</a>'
        run_link = f'<a href="{html.escape(run_url(finding.repository, finding.run_id))}">{finding.run_id}</a>'
        log_link = f'<a href="{html.escape(finding.log_path)}">{html.escape(finding.log_path)}</a>'
        date_value = finding.run_time_utc[:10] if finding.run_time_utc else ""
        run_time_value = finding.run_time_utc or ""
        matched_window = finding_exposure_match(finding)
        html_parts.append(
            "      <tr>"
            + f'<td data-sort-value="{html.escape(date_value)}">{maybe_red_html(date_value, matched_window)}</td>'
            + td(repo_link)
            + td(run_link)
            + f'<td data-sort-value="{html.escape(run_time_value)}">{maybe_red_html(run_time_value, matched_window)}</td>'
            + td(html.escape(finding.workflow))
            + td(html.escape(finding.usage_type))
            + td(format_trivy_details_html(finding))
            + td(html.escape(finding.ioc_match))
            + td(html.escape(finding.severity))
            + td(html.escape(finding.severity_trigger))
            + td(log_link)
            + td(html.escape(finding.evidence_snippet))
            + "</tr>"
        )
    html_parts.append("    </tbody>")
    html_parts.append("  </table>")

    html_parts.append("  <h2>All Scanned Runs</h2>")
    html_parts.append("  <table>")
    html_parts.append(
        "    <thead><tr><th>Date (UTC)</th><th>Repository</th><th>Run</th><th>Workflow</th><th>Status</th><th>Conclusion</th><th>Log Collected</th><th>Trivy Detected</th><th>Severity</th></tr></thead>"
    )
    html_parts.append("    <tbody>")
    for run in sorted(all_runs, key=lambda r: (r.created_at, r.repo, r.run_id)):
        key = (run.repo, run.run_id)
        finding = findings_by_run.get(key)
        matched_window = finding_exposure_match(finding) if finding else False
        repo_link = f'<a href="{html.escape(repo_url(run.repo))}">{html.escape(run.repo)}</a>'
        run_link = f'<a href="{html.escape(run_url(run.repo, run.run_id))}">{run.run_id}</a>'
        html_parts.append(
            "      <tr>"
            + td(maybe_red_html(run.created_at[:10] if run.created_at else "", matched_window))
            + td(repo_link)
            + td(run_link)
            + td(html.escape(run.workflow_name))
            + td(html.escape(run.status))
            + td(html.escape(run.conclusion))
            + td("yes" if key not in failed_runs else "no")
            + td("yes" if finding else "no")
            + td(html.escape(finding.severity if finding else ""))
            + "</tr>"
        )
    html_parts.append("    </tbody>")
    html_parts.append("  </table>")

    html_parts.append("  <h2>Flagged Items</h2>")
    if flagged:
        html_parts.append("  <ul>")
        for item in flagged:
            html_parts.append(
                "    <li>"
                f"{html.escape(item.severity)} {html.escape(item.repository)} run {item.run_id} "
                f"({html.escape(item.usage_type)}) {html.escape(item.log_path)}"
                "</li>"
            )
        html_parts.append("  </ul>")
    else:
        html_parts.append("  <p>None</p>")

    html_parts.append("  <h2>Collection Failures</h2>")
    if failed:
        html_parts.append("  <ul>")
        for item in failed:
            html_parts.append(
                f"    <li>{html.escape(item['repo'])} run {html.escape(item['run_id'])}: {html.escape(item['error'])}</li>"
            )
        html_parts.append("  </ul>")
    else:
        html_parts.append("  <p>None</p>")

    html_parts.append("  <script>")
    html_parts.append("    function sortFindingsBy(columnIndex, asc) {")
    html_parts.append("      const table = document.getElementById('findings-table');")
    html_parts.append("      if (!table) return;")
    html_parts.append("      const body = table.tBodies[0];")
    html_parts.append("      if (!body) return;")
    html_parts.append("      const rows = Array.from(body.rows);")
    html_parts.append("      rows.sort((a, b) => {")
    html_parts.append("        const aCell = a.cells[columnIndex];")
    html_parts.append("        const bCell = b.cells[columnIndex];")
    html_parts.append("        const aValue = (aCell && aCell.dataset && aCell.dataset.sortValue ? aCell.dataset.sortValue : (aCell ? aCell.textContent : '')).trim();")
    html_parts.append("        const bValue = (bCell && bCell.dataset && bCell.dataset.sortValue ? bCell.dataset.sortValue : (bCell ? bCell.textContent : '')).trim();")
    html_parts.append("        if (aValue === bValue) return 0;")
    html_parts.append("        return asc ? aValue.localeCompare(bValue) : bValue.localeCompare(aValue);")
    html_parts.append("      });")
    html_parts.append("      for (const row of rows) body.appendChild(row);")
    html_parts.append("    }")
    html_parts.append("  </script>")

    html_parts.append("</body>")
    html_parts.append("</html>")

    with open(output_path, "w", encoding="utf-8") as f:
        f.write("\n".join(html_parts))


def write_flags_file(flags_path: str, findings: List[Finding]) -> None:
    flagged = [x for x in findings if x.severity in {"CRITICAL", "HIGH"} or x.apt_0694_flag == "yes"]
    with open(flags_path, "w", encoding="utf-8") as f:
        for item in sorted(flagged, key=lambda x: (-SEVERITY_RANK[x.severity], x.repository, x.run_id)):
            f.write(f"{item.severity}\t{item.repository}\t{item.run_id}\tapt0.69.4={item.apt_0694_flag}\t{item.log_path}\n")
