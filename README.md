# trivyincident

`trivyincident` is a GitHub Actions incident-hunting scanner focused on known Trivy supply-chain compromise indicators during the March 19, 2026 incident.

## References

- https://github.com/aquasecurity/trivy/discussions/10425
- https://socket.dev/supply-chain-attacks/trivy-github-actions-compromise
- https://www.wiz.io/blog/trivy-compromised-teampcp-supply-chain-attack
- https://ramimac.me/trivy-teampcp/#iocs

## Exposure windows

| Component | Affected versions | NOT affected | Exposure window (UTC) | Duration |
| --- | --- | --- | --- | --- |
| **trivy** | v0.69.4 (latest tag also pointed to v0.69.4). GHCR, ECR Public, Docker Hub, deb, rpm, get.trivy.dev. | 1) v0.69.3 or earlier 2) Container images referenced by digest | 2026-03-19 18:22 – ~21:42 | ~3 hours |
| **trivy-action** | 1) All tags prior to 0.35.0 2) Explicitly requesting `version: latest` (not the default) during the trivy exposure window | 1) @0.35.0 2) SHA-pinned references since 2025-04-09 | 2026-03-19 ~17:43 – 2026-03-20 ~05:40 | ~12 hours |
| **setup-trivy** | All releases | SHA-pinned references | 2026-03-19 ~17:43 – ~21:44 | ~4 hours |

## What it does

- Enumerates repositories and workflow runs in a UTC time window.
- Downloads workflow run logs in parallel (up to 5 concurrent workers) with GitHub API rate-limit awareness.
- Automatically updates IOC databases from the upstream repository before scanning.
- Parses logs for Trivy-related activity:
  - GitHub Action usage (`aquasecurity/trivy-action`, `aquasecurity/setup-trivy`)
  - APT installation usage
  - Direct binary download usage (`curl`/`wget`)
  - Container usage (`docker run` + Trivy image)
- Matches extracted values against IOC databases:
  - Malicious workflow commit SHAs
  - Malicious binary SHA256 digests
  - Suspicious network indicators
  - Malicious Trivy versions (0.69.4, 0.69.5, 0.69.6)
- Checks the organization audit log for `tpcp-docs` repository creation (a known TeamPCP exfiltration indicator).
- Assigns severity and trigger rationale per finding.
- Produces all output in the `results/` directory:
  - `results/results.html` — interactive HTML report with sort controls, exposure window highlighting, and severity badges
  - `results/incident-report.pdf` — detailed incident PDF covering attack overview, flow diagrams, exposure windows, IOCs, affected repos, and remediation guidance
  - `results/logs/` — per-finding annotated log HTML files with evidence highlighted (when `--generate-log-html` is used)
  - `logs/flags.txt` — high-priority flat list for rapid escalation

## Limitations

- This tool only pulls and analyzes **GitHub Actions logs**.
- In live collection mode, scope is limited to repositories under the organization passed with `--org`.
- It does not collect logs from other CI systems (for example GitLab CI, Jenkins, CircleCI).
- It does not discover repositories outside the target organization unless those logs are already present locally and scanned via `--skip-run-listing`.

## Project layout

- `trivyincident.py` – CLI entrypoint/orchestrator.
- `trivyincident/` – reusable package modules:
  - `github_ops.py` – GitHub CLI/API operations.
  - `indicators.py` – IOC DB loading and auto-update.
  - `log_parser.py` – extraction, matching, severity logic.
  - `reporting.py` – HTML report and flags generation.
  - `pdf_report.py` – incident detail PDF generation.
  - `models.py` – dataclasses and severity ranking.
- `db/` – IOC databases.
- `tests/` – unit tests for parser and indicators.

## IOC databases

IOC files in `db/` are **automatically updated** from the upstream repository before each scan. To skip the update, pass `--no-update`.

- `workflow-sha.db` (or fallback `workflow_shas.db`)
- `binary-sha256.db` (or fallback `binary_sha256.db`)
- `network-ioc.db` (or fallback `network_iocs.db`)

Format: one IOC per line (comments with `#` allowed).

## Requirements

- Python 3.10+
- `reportlab` — `pip install reportlab` (for PDF report generation)
- GitHub CLI (`gh`) authenticated (`gh auth login`) for live collection mode
- **Organization audit log access** — the authenticated user must have access to the organization's audit log (organization owner or audit log reader role) for the `tpcp-docs` repo-creation IOC check

## Quick start (step by step)

```bash
# 1. Clone the repository
git clone https://github.com/ebvjrwork/trivyincident.git
cd trivyincident

# 2. Install dependencies
pip install -r requirements.txt

# 3. Authenticate with GitHub CLI (if not already)
gh auth login

# 4. Verify your GitHub auth works and you have org audit log access
gh auth status
gh api orgs/YOUR-ORG/audit-log -f phrase="action:repo.create" -f per_page=1

# 5. Run the scanner against your organization
python3 trivyincident.py \
  --org YOUR-ORG \
  --start 2026-03-19T00:00:00Z \
  --end   2026-03-22T20:00:00Z \
  --generate-log-html

# 6. Open the results
#    - results/results.html        — interactive HTML report
#    - results/incident-report.pdf — detailed incident PDF
#    - results/logs/               — per-finding annotated log files
#    - logs/flags.txt              — high-priority flat list
```

> **Note:** If the audit log API call in step 4 returns a 403, you need an org owner or audit log reader to grant access. The scanner will still work without it, but the `tpcp-docs` repo-creation IOC check will be skipped.

## Usage

### 1) Live collection scan (org-wide)

```bash
python3 trivyincident.py \
  --org your-org \
  --start 2026-03-19T00:00:00Z \
  --end   2026-03-21T20:00:00Z \
  --generate-log-html
```

### 2) Local log re-scan (skip GitHub listing)

```bash
python3 trivyincident.py \
  --org your-org \
  --start 2026-03-19T00:00:00Z \
  --end   2026-03-21T20:00:00Z \
  --skip-run-listing \
  --generate-log-html
```

### 3) Optional arguments

| Argument | Default | Description |
| --- | --- | --- |
| `--logs-root` | `logs` | Log storage directory |
| `--results-dir` | `results` | Output directory for HTML report and log HTMLs |
| `--db-root` | `db` | IOC database root |
| `--generate-log-html` | off | Generate per-finding annotated HTML log files |
| `--log-html-root` | `<results-dir>/logs/` | Custom output directory for log HTMLs |
| `--include-archived` | off | Include archived repos |
| `--max-repos N` | 0 (all) | Limit repository scan count |
| `--skip-run-listing` | off | Scan existing local logs, skip GitHub API |
| `--no-update` | off | Skip auto-updating IOC databases from upstream |

## How findings are determined

A finding is emitted when Trivy-related activity is detected in a run log.

Detection includes:
- Action references and action download SHAs
- APT package install patterns and version extraction
- Binary hashes observed in logs
- Known network IOC strings

Severity logic:
- **CRITICAL**: any IOC match (workflow SHA, binary hash, network IOC, malicious version 0.69.4/0.69.5/0.69.6, or audit-log tpcp-docs hit)
- **HIGH**: suspicious non-IOC risk pattern (risky action ref)
- **MEDIUM**: baseline Trivy activity without IOC/high-risk trigger

## Report output

### `results/results.html`

Interactive HTML report with sections:

1. **Info block** — Organization, run start/end (UTC).
2. **Summary cards** — Repos, runs, findings, CRITICAL, HIGH, logs new/reused, failures.
3. **Exposure Windows** — Reference table of affected components, versions, and time windows.
4. **Daily Summary** — Findings per day with GitHub Actions, APT, container, and severity counts.
5. **Findings table** — One row per detected run with evidence, severity badges, and sort controls (`▲`/`▼`).
6. **All Scanned Runs** — Coverage view showing which runs were scanned and whether Trivy was found.
7. **Flagged Items** — Quick list of CRITICAL/HIGH entries.
8. **Collection Failures** — Any log download errors.

Row highlighting:
- **Red row**: run time falls in a Trivy supply-chain exposure window (Trivy detected).
- **Amber row** (All Scanned Runs only): run time in exposure window, no Trivy detected.

### `results/incident-report.pdf`

Comprehensive incident PDF including:
- Executive summary with finding counts
- Attack overview (threat actor, vector, stages, impact)
- Supply-chain attack flow diagram
- Exposure window reference table
- Visual timeline with finding positions
- IOC details (binary hashes, network IOCs, workflow commit SHAs)
- Affected repositories summary table
- Per-finding detail tables with evidence
- Remediation guidance (immediate actions and preventive measures)
- Full reference links

### `results/logs/*.html`

Per-finding annotated log views with:
- Evidence lines highlighted in red
- `trivy` keyword, version numbers, and action refs highlighted inline

### `logs/flags.txt`

Plain-text shortlist for rapid escalation workflows.
Each line includes severity, repository, run id, IOC match, and log path.

## Interpreting severity quickly

- **CRITICAL**: treat as high-confidence compromise indicator hit; prioritize containment and artifact preservation.
- **HIGH**: suspicious pattern requiring prompt human review and context validation.
- **MEDIUM**: Trivy usage observed, but no direct IOC/risk trigger matched.

## Testing

Run unit tests:

```bash
python3 -m unittest discover -s tests -v
```

## Typical incident workflow

1. IOC databases auto-update from upstream (or update manually in `db/`).
2. Run live scan over incident window.
3. Review `results/results.html` sorted by run time.
4. Triage `CRITICAL` and `HIGH` first.
5. Use run links and evidence snippets to confirm context in GitHub.
6. Re-run in `--skip-run-listing` mode for fast iterative analysis.
