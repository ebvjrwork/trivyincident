import html
import os
import re
from datetime import datetime, timezone
from typing import Dict, List, Optional, Set, Tuple

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
        malicious_versions = {"0.69.4", "0.69.5", "0.69.6"}
        has_malicious = any(v in malicious_versions for v in versions) or any(v in detail_text for v in malicious_versions)
        if has_malicious:
            component = "trivy"

    if not component:
        return False
    start_dt, end_dt = EXPOSURE_WINDOWS[component]
    return start_dt <= run_dt <= end_dt


def run_in_any_exposure_window(ts: str) -> Optional[str]:
    """Return the first exposure window name the timestamp falls in, or None."""
    dt = _parse_utc_iso(ts)
    if dt is None:
        return None
    for name, (start, end) in EXPOSURE_WINDOWS.items():
        if start <= dt <= end:
            return name
    return None


def maybe_red_md(value: str, should_highlight: bool) -> str:
    return red_md(value) if should_highlight and value else value


def maybe_red_html(value: str, should_highlight: bool) -> str:
    escaped = html.escape(value)
    return f'<span class="dt-red">{escaped}</span>' if should_highlight and value else escaped


def format_evidence_snippet_html(finding: Finding) -> str:
    """Return a highlighted HTML block for the evidence snippet."""
    if not finding.evidence_snippet:
        return ""
    versions = [v.strip() for v in (finding.version or "").split(",") if v.strip()]
    parts: List[str] = []
    for segment in finding.evidence_snippet.split(" || "):
        segment = segment.strip()
        if not segment:
            continue
        esc = html.escape(segment)
        # Highlight action refs (before trivy keyword so 'trivy' inside isn't double-wrapped)
        esc = re.sub(
            r"(?i)(aquasecurity/(?:trivy-action|setup-trivy)@[A-Za-z0-9._/\-]+)",
            r'<span class="evidence-hit">\1</span>',
            esc,
        )
        # Highlight version numbers
        for v in versions:
            if v:
                esc = esc.replace(html.escape(v), f'<span class="evidence-hit">{html.escape(v)}</span>')
        # Highlight SHA-40 / SHA-64 hashes
        esc = re.sub(r"([0-9a-f]{40,64})", r'<span class="evidence-hit">\1</span>', esc, flags=re.IGNORECASE)
        # Highlight 'trivy' keyword where not already inside a span
        esc = re.sub(r"(?i)\b(trivy)\b", r'<span class="evidence-hit">\1</span>', esc)
        parts.append(f'<div class="ev-seg">{esc}</div>')
    return "\n".join(parts)


# ──────────────────────────────────────────────────────────────────────────────
# Per-log HTML helpers
# ──────────────────────────────────────────────────────────────────────────────

_LOG_SECTION_HEADER_RE = re.compile(r"^=====\s+(.+?)\s+=====$")
_LOG_ANSI_RE = re.compile(r"\x1B\[[0-?]*[ -/]*[@-~]")
_LOG_TS_RE = re.compile(r"\b(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z)\b")


def _highlight_log_line_html(raw_line: str, versions: List[str]) -> str:
    """Strip ANSI codes, HTML-escape, then apply inline evidence highlighting."""
    clean = _LOG_ANSI_RE.sub("", raw_line.rstrip())
    result = html.escape(clean)
    # Action refs first (contain 'trivy', handle before the trivy keyword sweep)
    result = re.sub(
        r"(?i)(aquasecurity/(?:trivy-action|setup-trivy)@[A-Za-z0-9._/\-]+)",
        r'<span class="hl-action">\1</span>',
        result,
    )
    # Version numbers
    for v in versions:
        if v:
            result = result.replace(html.escape(v), f'<span class="hl-version">{html.escape(v)}</span>')
    # Trivy keyword
    result = re.sub(r"(?i)\b(trivy)\b", r'<span class="hl-trivy">\1</span>', result)
    return result


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


def write_results_html(
    output_path: str,
    org: str,
    run_start_iso: str,
    run_end_iso: str,
    repos_scanned: int,
    total_runs: int,
    downloaded: int,
    skipped_existing: int,
    failed: List[Dict[str, str]],
    findings: List[Finding],
    all_runs: List[RunInfo],
    log_html_root: Optional[str] = None,
) -> None:
    findings_sorted = sorted(findings, key=lambda f: (-SEVERITY_RANK[f.severity], f.repository, f.run_id))
    findings_by_run: Dict[Tuple[str, int], Finding] = {(f.repository, f.run_id): f for f in findings_sorted}
    failed_runs: Set[Tuple[str, int]] = {(item["repo"], int(item["run_id"])) for item in failed}

    daily: Dict[str, Dict[str, int]] = {}
    for item in findings_sorted:
        day = item.run_time_utc[:10] if item.run_time_utc else "unknown"
        if day not in daily:
            daily[day] = {"total": 0, "action": 0, "apt": 0, "container": 0, "high": 0, "critical": 0}
        daily[day]["total"] += 1
        if item.usage_type == "action":
            daily[day]["action"] += 1
        if item.usage_type == "apt":
            daily[day]["apt"] += 1
        if item.usage_type == "container":
            daily[day]["container"] += 1
        if item.severity == "HIGH":
            daily[day]["high"] += 1
        if item.severity == "CRITICAL":
            daily[day]["critical"] += 1

    flagged = [x for x in findings_sorted if x.severity in {"CRITICAL", "HIGH"}]

    n_critical = sum(1 for f in findings_sorted if f.severity == "CRITICAL")
    n_high = sum(1 for f in findings_sorted if f.severity == "HIGH")

    def td(value: str, cls: str = "") -> str:
        attr = f' class="{cls}"' if cls else ""
        return f"<td{attr}>{value}</td>"

    CSS = """
    *, *::before, *::after { box-sizing: border-box; }
    :root {
      --brand:   #1a56db;
      --brand-dk:#1340a8;
      --danger:  #c0392b;
      --warn:    #d97706;
      --ok:      #16a34a;
      --bg:      #f8fafc;
      --surface: #ffffff;
      --border:  #e2e8f0;
      --text:    #0f172a;
      --muted:   #64748b;
    }
    body {
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      margin: 0; background: var(--bg); color: var(--text); font-size: 14px; line-height: 1.5;
    }
    /* ── top nav bar ── */
    .topbar {
      background: var(--brand); color: #fff; padding: 0 28px;
      display: flex; align-items: center; gap: 12px; height: 52px;
      box-shadow: 0 2px 6px rgba(0,0,0,.18);
    }
    .topbar-logo { font-size: 20px; font-weight: 700; letter-spacing: -.5px; }
    .topbar-sub  { font-size: 13px; opacity: .8; }
    /* ── page wrapper ── */
    .page { max-width: 1600px; margin: 0 auto; padding: 28px 28px 60px; }
    /* ── meta cards (summary row) ── */
    .meta-grid {
      display: grid; grid-template-columns: repeat(auto-fill, minmax(170px, 1fr));
      gap: 12px; margin: 24px 0;
    }
    .meta-card {
      background: var(--surface); border: 1px solid var(--border);
      border-radius: 8px; padding: 14px 16px; box-shadow: 0 1px 3px rgba(0,0,0,.06);
    }
    .meta-card .mc-label { font-size: 11px; text-transform: uppercase;
      letter-spacing: .06em; color: var(--muted); margin-bottom: 4px; }
    .meta-card .mc-value { font-size: 22px; font-weight: 700; line-height: 1.1; }
    .mc-danger .mc-value { color: var(--danger); }
    .mc-warn   .mc-value { color: var(--warn); }
    .mc-ok     .mc-value { color: var(--ok); }
    /* ── section headings ── */
    h2 { font-size: 17px; font-weight: 700; margin: 32px 0 10px; padding-bottom: 6px;
         border-bottom: 2px solid var(--brand); color: var(--brand-dk); }
    h2:first-of-type { margin-top: 0; }
    /* ── info block (org / window) ── */
    .info-block {
      background: var(--surface); border: 1px solid var(--border);
      border-radius: 8px; padding: 14px 20px; display: flex; flex-wrap: wrap;
      gap: 8px 32px; font-size: 13px; margin-bottom: 20px;
      box-shadow: 0 1px 3px rgba(0,0,0,.06);
    }
    .info-block .ib-item { display: flex; flex-direction: column; }
    .info-block .ib-label { font-size: 11px; text-transform: uppercase;
      letter-spacing: .06em; color: var(--muted); }
    .info-block .ib-value { font-weight: 600; }
    /* ── legend ── */
    .legend { font-size: 12px; color: var(--muted); margin-bottom: 10px; display: flex; gap: 16px; flex-wrap: wrap; }
    .legend-swatch { display: inline-block; width: 12px; height: 12px;
      vertical-align: middle; margin-right: 4px; border-radius: 2px; }
    /* ── tables ── */
    .tbl-wrap { overflow-x: auto; border-radius: 8px;
      border: 1px solid var(--border); margin-bottom: 28px;
      box-shadow: 0 1px 4px rgba(0,0,0,.06); }
    table { border-collapse: collapse; width: 100%; background: var(--surface); }
    thead th {
      background: #f1f5f9; font-size: 12px; font-weight: 600;
      text-transform: uppercase; letter-spacing: .05em;
      padding: 10px 12px; border-bottom: 2px solid var(--border);
      white-space: nowrap; text-align: left; position: sticky; top: 0;
    }
    tbody td { padding: 8px 12px; font-size: 13px; vertical-align: top;
               border-bottom: 1px solid var(--border); }
    tbody tr:last-child td { border-bottom: none; }
    tbody tr:hover td { background: #f0f7ff !important; }
    /* ── row severity colouring ── */
    tr.row-exposed td { background: #fff0f0 !important; border-left: 3px solid var(--danger); }
    tr.row-in-window td { background: #fffbeb !important; border-left: 3px solid var(--warn); }
    /* ── sort buttons ── */
    .sort-btn {
      border: none; background: transparent; cursor: pointer; padding: 0 3px;
      color: #94a3b8; font-size: 11px; line-height: 1; vertical-align: middle;
    }
    .sort-btn:hover { color: var(--brand); }
    /* ── severity badges ── */
    .badge {
      display: inline-block; padding: 2px 8px; border-radius: 9999px;
      font-size: 11px; font-weight: 700; text-transform: uppercase; letter-spacing: .04em;
    }
    .badge-critical { background: #fee2e2; color: #991b1b; }
    .badge-high     { background: #ffedd5; color: #9a3412; }
    .badge-medium   { background: #fef9c3; color: #713f12; }
    .badge-low      { background: #dcfce7; color: #14532d; }
    .badge-info     { background: #dbeafe; color: #1e40af; }
    /* ── dt-red ── */
    .dt-red { color: var(--danger); font-weight: 600; }
    /* ── evidence snippet ── */
    .snippet-cell {
      font-family: "SFMono-Regular", "Cascadia Code", Menlo, monospace;
      font-size: 11px; word-break: break-all; max-width: 440px;
    }
    .ev-seg { padding: 2px 0; border-bottom: 1px dotted #e2e8f0; }
    .ev-seg:last-child { border-bottom: none; }
    .evidence-hit {
      background: #fecaca; color: #7f1d1d; font-weight: 700;
      padding: 1px 4px; border-radius: 3px;
    }
    /* ── links ── */
    a { color: var(--brand); text-decoration: none; }
    a:hover { text-decoration: underline; }
    a.log-view { font-size: 11px; white-space: nowrap; }
    /* ── flagged list ── */
    .flagged-list { list-style: none; padding: 0; margin: 0; display: flex; flex-direction: column; gap: 6px; }
    .flagged-list li {
      background: var(--surface); border: 1px solid var(--border);
      border-radius: 6px; padding: 8px 14px; font-size: 13px;
      display: flex; gap: 10px; align-items: baseline; flex-wrap: wrap;
    }
    .fl-repo { font-weight: 600; }
    .fl-meta { color: var(--muted); font-size: 12px; }
    /* ── ioc sources ── */
    .ioc-sources { font-size: 12px; color: var(--muted); margin-top: 8px; }
    /* ── footer ── */
    .site-footer {
      margin-top: 48px; padding: 20px 0; border-top: 1px solid var(--border);
      font-size: 12px; color: var(--muted); text-align: center;
    }
    .site-footer a { color: var(--brand); }
    """

    P: List[str] = []
    P.append("<!doctype html>")
    P.append('<html lang="en">')
    P.append("<head>")
    P.append('  <meta charset="utf-8">')
    P.append('  <meta name="viewport" content="width=device-width, initial-scale=1">')
    P.append("  <title>trivyincident &mdash; Scan Results</title>")
    P.append(f"  <style>{CSS}</style>")
    P.append("</head>")
    P.append("<body>")

    # Top bar
    P.append('  <div class="topbar">')
    P.append('    <a href="https://github.com/ebvjrwork/trivyincident" class="topbar-logo" style="color:#fff;text-decoration:none">trivyincident</a>')
    P.append("  </div>")

    P.append('  <div class="page">')

    # Info block
    P.append('  <div class="info-block">')
    P.append(f'    <div class="ib-item"><span class="ib-label">Organization</span><span class="ib-value">{html.escape(org)}</span></div>')
    P.append(f'    <div class="ib-item"><span class="ib-label">Run Start (UTC)</span><span class="ib-value">{html.escape(run_start_iso)}</span></div>')
    P.append(f'    <div class="ib-item"><span class="ib-label">Run End (UTC)</span><span class="ib-value">{html.escape(run_end_iso)}</span></div>')
    P.append("  </div>")

    # Summary cards
    P.append('  <div class="meta-grid">')
    cards = [
        ("Repositories", str(repos_scanned), ""),
        ("Runs in window", str(total_runs), ""),
        ("Findings", str(len(findings_sorted)), "mc-warn" if findings_sorted else "mc-ok"),
        ("CRITICAL", str(n_critical), "mc-danger" if n_critical else ""),
        ("HIGH", str(n_high), "mc-warn" if n_high else ""),
        ("Logs new", str(downloaded), ""),
        ("Logs reused", str(skipped_existing), ""),
        ("Failures", str(len(failed)), "mc-danger" if failed else "mc-ok"),
    ]
    for label, val, cls in cards:
        card_cls = f"meta-card {cls}".strip()
        P.append(f'    <div class="{card_cls}"><div class="mc-label">{label}</div><div class="mc-value">{val}</div></div>')
    P.append("  </div>")

    P.append('  <div class="ioc-sources">IOC sources: '
             '<a href="https://socket.dev/supply-chain-attacks/trivy-github-actions-compromise">socket.dev</a>, '
             '<a href="https://www.wiz.io/blog/trivy-compromised-teampcp-supply-chain-attack">wiz.io</a>, '
             '<a href="https://github.com/aquasecurity/trivy/discussions/10425">aquasecurity/trivy#10425</a>, '
             '<a href="https://ramimac.me/trivy-teampcp/#iocs">ramimac.me</a></div>')

    # Exposure windows reference table
    P.append('  <h2>Exposure Windows</h2>')
    P.append('  <div class="tbl-wrap"><table>')
    P.append('    <thead><tr>'
             '<th>Component</th><th>Affected versions</th><th>NOT affected</th>'
             '<th>Exposure window (UTC)</th><th>Duration</th></tr></thead>')
    P.append('    <tbody>')
    P.append('      <tr>'
             '<td><strong>trivy</strong></td>'
             '<td>v0.69.4 (latest tag also pointed to v0.69.4). GHCR, ECR&nbsp;Public, Docker&nbsp;Hub, deb, rpm, get.trivy.dev.</td>'
             '<td>1)&nbsp;v0.69.3 or earlier<br>2)&nbsp;Container images referenced by digest</td>'
             '<td>2026-03-19 18:22 &ndash; ~21:42</td>'
             '<td>~3&nbsp;hours</td></tr>')
    P.append('      <tr>'
             '<td><strong>trivy-action</strong></td>'
             '<td>1)&nbsp;All tags prior to 0.35.0<br>2)&nbsp;Explicitly requesting <code>version:&nbsp;latest</code> (not the default) during the trivy exposure window</td>'
             '<td>1)&nbsp;@0.35.0<br>2)&nbsp;SHA-pinned references since 2025-04-09</td>'
             '<td>2026-03-19 ~17:43 &ndash; 2026-03-20 ~05:40</td>'
             '<td>~12&nbsp;hours</td></tr>')
    P.append('      <tr>'
             '<td><strong>setup-trivy</strong></td>'
             '<td>All releases</td>'
             '<td>SHA-pinned references</td>'
             '<td>2026-03-19 ~17:43 &ndash; ~21:44</td>'
             '<td>~4&nbsp;hours</td></tr>')
    P.append('    </tbody>')
    P.append('  </table></div>')

    # Daily summary
    P.append("  <h2>Daily Summary</h2>")
    P.append('  <div class="tbl-wrap"><table>')
    P.append("    <thead><tr><th>Date (UTC)</th><th>Trivy Findings</th><th>GitHub Actions Usage</th><th>APT Usage</th><th>Container Usage</th><th>HIGH</th><th>CRITICAL</th></tr></thead>")
    P.append("    <tbody>")
    for day in sorted(daily.keys()):
        entry = daily[day]
        P.append(
            "      <tr>"
            + td(html.escape(day))
            + td(str(entry["total"]))
            + td(str(entry["action"]))
            + td(str(entry["apt"]))
            + td(str(entry["container"]))
            + td(str(entry["high"]))
            + td(str(entry["critical"]))
            + "</tr>"
        )
    P.append("    </tbody>")
    P.append("  </table></div>")

    # Findings table
    P.append("  <h2>Findings</h2>")
    P.append(
        "  <div class=\"legend\">"
        "<span><span class='legend-swatch' style='background:#fee2e2;border-left:3px solid #c0392b'></span>"
        "<strong>Red row</strong>: run time in Trivy supply-chain exposure window (Trivy detected)</span>"
        "<span><span class='legend-swatch' style='background:#fffbeb;border-left:3px solid #d97706'></span>"
        "<strong>Amber row</strong> (All Scanned Runs): run time in exposure window, no Trivy detected</span>"
        "</div>"
    )
    _log_view_col = "<th>Log View</th>" if log_html_root else ""
    P.append('  <div class="tbl-wrap"><table id="findings-table">')
    P.append(
        "    <thead><tr>"
        "<th>Run Time (UTC)"
        '<button type="button" class="sort-btn" onclick="sortFindingsBy(0,true)" title="Ascending">▲</button>'
        '<button type="button" class="sort-btn" onclick="sortFindingsBy(0,false)" title="Descending">▼</button>'
        "</th>"
        "<th>Repository</th><th>Run</th><th>Workflow</th><th>Usage Type</th>"
        "<th>Trivy Details</th><th>IOC Match</th><th>Severity</th><th>Severity Trigger</th>"
        "<th>Evidence Snippet</th>"
        + _log_view_col
        + "</tr></thead>"
    )
    P.append("    <tbody>")

    def _severity_badge(sev: str) -> str:
        cls = {"CRITICAL": "badge-critical", "HIGH": "badge-high",
               "MEDIUM": "badge-medium", "LOW": "badge-low"}.get(sev.upper(), "badge-info")
        return f'<span class="badge {cls}">{html.escape(sev)}</span>'

    for finding in findings_sorted:
        repo_link = f'<a href="{html.escape(repo_url(finding.repository))}">{html.escape(finding.repository)}</a>'
        run_link = f'<a href="{html.escape(run_url(finding.repository, finding.run_id))}">{finding.run_id}</a>'
        run_time_value = finding.run_time_utc or ""
        matched_window = finding_exposure_match(finding)
        has_ioc = bool(finding.ioc_match)
        row_class = ' class="row-exposed"' if (matched_window or has_ioc) else ""
        log_view_td = ""
        if log_html_root:
            repo_name = finding.repository.split("/", 1)[1]
            log_html_path = os.path.join(log_html_root, repo_name, f"{finding.run_id}.html")
            rel = os.path.relpath(log_html_path, os.path.dirname(os.path.abspath(output_path)))
            log_view_td = f'<td><a class="log-view" href="{html.escape(rel)}">view log ↗</a></td>'
        P.append(
            f"      <tr{row_class}>"
            + f'<td data-sort-value="{html.escape(run_time_value)}">{maybe_red_html(run_time_value, matched_window)}</td>'
            + td(repo_link)
            + td(run_link)
            + td(html.escape(finding.workflow))
            + td(html.escape(finding.usage_type))
            + td(format_trivy_details_html(finding))
            + td(f'<span class="dt-red">{html.escape(finding.ioc_match)}</span>' if finding.ioc_match else "")
            + td(_severity_badge(finding.severity))
            + td(html.escape(finding.severity_trigger))
            + f'<td class="snippet-cell">{format_evidence_snippet_html(finding)}</td>'
            + log_view_td
            + "</tr>"
        )
    P.append("    </tbody>")
    P.append("  </table></div>")

    # All scanned runs
    P.append("  <h2>All Scanned Runs</h2>")
    P.append('  <div class="tbl-wrap"><table>')
    P.append(
        "    <thead><tr>"
        "<th>Run Time (UTC)</th><th>Repository</th><th>Run</th>"
        "<th>Workflow</th><th>Status</th><th>Conclusion</th>"
        "<th>Log Collected</th><th>Trivy Detected</th><th>Severity</th>"
        "</tr></thead>"
    )
    P.append("    <tbody>")
    for run in sorted(all_runs, key=lambda r: (r.created_at, r.repo, r.run_id)):
        key = (run.repo, run.run_id)
        finding = findings_by_run.get(key)
        matched_window = finding_exposure_match(finding) if finding else False
        in_window_name = run_in_any_exposure_window(run.created_at) if not matched_window and run.created_at else None
        row_class = ' class="row-exposed"' if matched_window else (' class="row-in-window"' if in_window_name else "")
        repo_link = f'<a href="{html.escape(repo_url(run.repo))}">{html.escape(run.repo)}</a>'
        run_link = f'<a href="{html.escape(run_url(run.repo, run.run_id))}">{run.run_id}</a>'
        sev_cell = _severity_badge(finding.severity) if finding and finding.severity else ""
        P.append(
            f"      <tr{row_class}>"
            + td(maybe_red_html(run.created_at if run.created_at else "", matched_window))
            + td(repo_link)
            + td(run_link)
            + td(html.escape(run.workflow_name))
            + td(html.escape(run.status))
            + td(html.escape(run.conclusion))
            + td("yes" if key not in failed_runs else "no")
            + td("yes" if finding else "no")
            + td(sev_cell)
            + "</tr>"
        )
    P.append("    </tbody>")
    P.append("  </table></div>")

    # Flagged
    P.append("  <h2>Flagged Items</h2>")
    if flagged:
        P.append('  <ul class="flagged-list">')
        for item in flagged:
            run_h = f'<a href="{html.escape(run_url(item.repository, item.run_id))}">{item.run_id}</a>'
            P.append(
                "    <li>"
                + _severity_badge(item.severity) + " "
                + f'<span class="fl-repo">{html.escape(item.repository)}</span> '
                + f'run {run_h} '
                + f'<span class="fl-meta">({html.escape(item.usage_type)}) {html.escape(item.log_path)}</span>'
                + "</li>"
            )
        P.append("  </ul>")
    else:
        P.append("  <p style='color:var(--ok);font-weight:600'>No flagged items.</p>")

    # Collection failures
    P.append("  <h2>Collection Failures</h2>")
    if failed:
        P.append('  <div class="tbl-wrap"><table>')
        P.append("    <thead><tr><th>Repository</th><th>Run ID</th><th>Error</th></tr></thead>")
        P.append("    <tbody>")
        for item in failed:
            P.append(
                "      <tr>"
                + td(html.escape(item["repo"]))
                + td(html.escape(item["run_id"]))
                + td(html.escape(item["error"]))
                + "</tr>"
            )
        P.append("    </tbody>")
        P.append("  </table></div>")
    else:
        P.append("  <p style='color:var(--ok);font-weight:600'>No collection failures.</p>")

    # JS sort
    P.append("  <script>")
    P.append("""    function sortFindingsBy(col, asc) {
      const tbl = document.getElementById('findings-table');
      if (!tbl) return;
      const body = tbl.tBodies[0];
      const rows = Array.from(body.rows);
      rows.sort((a, b) => {
        const av = (a.cells[col]?.dataset?.sortValue ?? a.cells[col]?.textContent ?? '').trim();
        const bv = (b.cells[col]?.dataset?.sortValue ?? b.cells[col]?.textContent ?? '').trim();
        return asc ? av.localeCompare(bv) : bv.localeCompare(av);
      });
      rows.forEach(r => body.appendChild(r));
    }""")
    P.append("  </script>")

    P.append('  <footer class="site-footer">')
    P.append('    by: <a href="https://github.com/ebvjrwork">ebvjrwork</a> with help of Claude Opus 4.6')
    P.append('  </footer>')
    P.append("  </div>")  # .page
    P.append("</body>")
    P.append("</html>")

    os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        f.write("\n".join(P))


def write_log_html(log_path: str, finding: Finding, out_path: str) -> None:
    """Generate an annotated HTML view of a single log file with evidence lines highlighted in red."""
    in_window = finding_exposure_match(finding)
    window_name = run_in_any_exposure_window(finding.run_time_utc)
    versions = [v.strip() for v in (finding.version or "").split(",") if v.strip()]
    ioc_tokens: List[str] = []
    for tok in (finding.ioc_match or "").split(","):
        tok = tok.strip()
        if ":" in tok:
            val = tok.split(":", 1)[-1].strip()
            if val and len(val) > 8:
                ioc_tokens.append(val.lower())

    try:
        with open(log_path, encoding="utf-8", errors="replace") as f:
            log_lines = f.readlines()
    except OSError:
        return

    def _is_evidence(line: str) -> bool:
        lc = line.lower()
        if "trivy" in lc:
            return True
        for v in versions:
            if v.lower() in lc:
                return True
        for ioc in ioc_tokens:
            if ioc in lc:
                return True
        return False

    line_parts: List[str] = []
    for idx, raw_line in enumerate(log_lines):
        stripped = raw_line.strip()
        section_m = _LOG_SECTION_HEADER_RE.match(stripped)
        if section_m:
            title = html.escape(section_m.group(1))
            line_parts.append(
                f'<div class="log-section" id="sec-{idx}">'
                f'<span class="ln">{idx + 1:6d}</span> '
                f'<span class="section-title">═══ {title} ═══</span></div>'
            )
            continue
        ev = _is_evidence(raw_line)
        row_cls = ' class="ev-line"' if ev else ""
        highlighted = _highlight_log_line_html(raw_line, versions)
        line_parts.append(f'<div{row_cls}><span class="ln">{idx + 1:6d}</span> {highlighted}</div>')

    banner_html = ""
    if in_window and window_name:
        s, e = EXPOSURE_WINDOWS[window_name]
        banner_html = (
            f'<div class="window-banner">'
            f'&#9888; RUN TIME <strong>{html.escape(finding.run_time_utc)}</strong> falls in the '
            f'<strong>{html.escape(window_name)}</strong> exposure window '
            f'({s.strftime("%Y-%m-%dT%H:%MZ")} &ndash; {e.strftime("%Y-%m-%dT%H:%MZ")}). '
            f'This run may have been affected by the Trivy supply chain compromise.'
            f'</div>'
        )

    run_time_html = (
        f'<span style="color:#c00;font-weight:bold">{html.escape(finding.run_time_utc)}</span>'
        if in_window else html.escape(finding.run_time_utc)
    )

    page = "\n".join([
        "<!doctype html>",
        '<html lang="en">',
        "<head>",
        '  <meta charset="utf-8">',
        '  <meta name="viewport" content="width=device-width, initial-scale=1">',
        f"  <title>Log: {html.escape(os.path.basename(log_path))} &mdash; {html.escape(finding.repository)}</title>",
        "  <style>",
        "    * { box-sizing: border-box; margin: 0; padding: 0; }",
        "    body { font-family: Arial, sans-serif; font-size: 13px; color: #111; }",
        "    .page-header { background: #f5f5f5; border-bottom: 2px solid #ddd; padding: 14px 20px; }",
        "    .page-header h1 { font-size: 15px; margin: 0 0 10px 0; word-break: break-all; color: #333; }",
        "    .meta-table { border-collapse: collapse; font-size: 12px; }",
        "    .meta-table td { padding: 2px 12px 2px 0; vertical-align: top; }",
        "    .meta-table td:first-child { font-weight: bold; white-space: nowrap; width: 130px; }",
        "    .window-banner { background: #b00; color: #fff; padding: 10px 20px; font-size: 13px; font-weight: bold; }",
        "    .evidence-note { background: #fff8e1; border: 1px solid #ffe082; padding: 6px 14px; margin: 8px 20px; font-size: 12px; }",
        "    .log-body { padding: 4px 0; overflow-x: auto; }",
        "    .log-body div { font-family: 'Courier New', monospace; font-size: 11.5px; white-space: pre; line-height: 1.55; padding: 0 6px; }",
        "    .ev-line { background: #fff0f0 !important; border-left: 4px solid #c00; }",
        "    .log-section { background: #eef2ff; border-left: 4px solid #66c; padding: 2px 8px; }",
        "    .section-title { color: #338; font-weight: bold; }",
        "    .ln { color: #bbb; display: inline-block; min-width: 52px; text-align: right; padding-right: 14px; user-select: none; }",
        "    .hl-trivy { background: #ffe0e0; color: #900; font-weight: bold; }",
        "    .hl-version { background: #ffd0d0; color: #800; font-weight: bold; }",
        "    .hl-action { background: #ffe8b0; color: #740; font-weight: bold; }",
        "    .dt-red { color: #c00; font-weight: bold; }",
        "    a { color: #0066cc; }",
        "  </style>",
        "</head>",
        "<body>",
        "  <div class=\"page-header\">",
        f'    <h1>Log: {html.escape(log_path)}</h1>',
        '    <table class="meta-table">',
        f'      <tr><td>Repository</td><td><a href="{html.escape(repo_url(finding.repository))}">{html.escape(finding.repository)}</a></td></tr>',
        f'      <tr><td>Run ID</td><td><a href="{html.escape(run_url(finding.repository, finding.run_id))}">{finding.run_id}</a></td></tr>',
        f"      <tr><td>Run Time (UTC)</td><td>{run_time_html}</td></tr>",
        f"      <tr><td>Workflow</td><td>{html.escape(finding.workflow)}</td></tr>",
        f"      <tr><td>Severity</td><td><strong>{html.escape(finding.severity)}</strong> &mdash; {html.escape(finding.severity_trigger)}</td></tr>",
        f"      <tr><td>Usage Type</td><td>{html.escape(finding.usage_type)}</td></tr>",
        f"      <tr><td>Trivy Details</td><td>{format_trivy_details_html(finding)}</td></tr>",
        (f"      <tr><td>IOC Match</td><td>{html.escape(finding.ioc_match)}</td></tr>" if finding.ioc_match else ""),
        "    </table>",
        "  </div>",
        f"  {banner_html}",
        "  <div class=\"evidence-note\">",
        "    Lines highlighted in "
        "<span style='background:#fff0f0;border-left:3px solid #c00;padding:1px 6px;font-family:monospace'>red</span>"
        " contain Trivy references or version evidence. &nbsp;"
        "<span class='hl-trivy' style='padding:1px 4px;font-family:monospace'>trivy</span> keyword, "
        "<span class='hl-version' style='padding:1px 4px;font-family:monospace'>version</span> numbers, and "
        "<span class='hl-action' style='padding:1px 4px;font-family:monospace'>action refs</span> are highlighted inline.",
        "  </div>",
        '  <div class="log-body">',
        "".join(line_parts),
        "  </div>",
        "</body>",
        "</html>",
    ])

    os.makedirs(os.path.dirname(os.path.abspath(out_path)), exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as fout:
        fout.write(page)


def write_flags_file(flags_path: str, findings: List[Finding]) -> None:
    flagged = [x for x in findings if x.severity in {"CRITICAL", "HIGH"}]
    with open(flags_path, "w", encoding="utf-8") as f:
        for item in sorted(flagged, key=lambda x: (-SEVERITY_RANK[x.severity], x.repository, x.run_id)):
            f.write(f"{item.severity}\t{item.repository}\t{item.run_id}\t{item.ioc_match or '-'}\t{item.log_path}\n")
