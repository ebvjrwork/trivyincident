# trivyincident

`trivyincident` is a GitHub Actions incident-hunting scanner focused on known Trivy supply-chain compromise indicators during the March 19, 2026 incident.

Reference discussion: https://github.com/aquasecurity/trivy/discussions/10425

It scans workflow run logs across an organization (or scans already-downloaded logs), detects suspicious Trivy usage patterns, correlates findings against IOC databases, and generates investigation-friendly reports in Markdown and HTML.

## What it does

- Enumerates repositories and workflow runs in a UTC time window.
- Downloads workflow run logs for each run (with fallback retrieval path).
- Parses logs for Trivy-related activity:
  - GitHub Action usage (`aquasecurity/trivy-action`, `aquasecurity/setup-trivy`)
  - APT installation usage
  - Direct binary download usage (`curl`/`wget`)
  - Container usage (`docker run` + Trivy image)
- Matches extracted values against IOC databases:
  - Malicious workflow commit SHAs
  - Malicious binary SHA256 digests
  - Suspicious network indicators
- Assigns severity and trigger rationale per finding.
- Produces:
  - `results.md` (detailed markdown report)
  - `results.html` (interactive report with sort controls)
  - `logs/flags.txt` (high-priority flat list)

## Why this is useful

- Designed for rapid triage during a supply-chain incident window.
- Separates IOC data from code, so updates are easy and low-risk.
- Preserves evidence snippets in output to speed human investigation.
- Supports two workflows:
  - **Live collection mode**: query GitHub and pull logs now.
  - **Offline/local mode**: re-scan existing logs without API listing.

## Limitations

- This tool only pulls and analyzes **GitHub Actions logs**.
- In live collection mode, scope is limited to repositories under the organization passed with `--org`.
- It does not collect logs from other CI systems (for example GitLab CI, Jenkins, CircleCI).
- It does not discover repositories outside the target organization unless those logs are already present locally and scanned via `--skip-run-listing`.

## Project layout

- `trivyincident.py` – CLI entrypoint/orchestrator.
- `trivyincident/` – reusable package modules:
  - `github_ops.py` – GitHub CLI/API operations.
  - `indicators.py` – IOC DB loading.
  - `log_parser.py` – extraction, matching, severity logic.
  - `reporting.py` – markdown/html/flags report generation.
  - `models.py` – dataclasses and severity ranking.
- `db/` – IOC databases.
- `tests/` – unit tests for parser and indicators.

## IOC databases

Place/update IOC files in `db/`:

- `workflow-sha.db` (or fallback `workflow_shas.db`)
- `binary-sha256.db` (or fallback `binary_sha256.db`)
- `network-ioc.db` (or fallback `network_iocs.db`)

Format: one IOC per line (comments with `#` allowed).

## Requirements

- Python 3.10+
- GitHub CLI (`gh`) authenticated (`gh auth login`) for live collection mode

## Usage

### 1) Live collection scan (org-wide)

```bash
python3 trivyincident.py \
  --org your-org \
  --start 2026-03-19T00:00:00Z \
  --end   2026-03-21T20:00:00Z
```

### 2) Local log re-scan (skip GitHub listing)

```bash
python3 trivyincident.py \
  --org your-org \
  --start 2026-03-19T00:00:00Z \
  --end   2026-03-21T20:00:00Z \
  --skip-run-listing
```

### 3) Optional arguments

- `--logs-root logs` – log storage directory
- `--report results.md` – markdown output file
- `--html-report results.html` – html output file
- `--db-root db` – IOC database root
- `--include-archived` – include archived repos
- `--max-repos N` – limit repository scan count

## How findings are determined

A finding is emitted when Trivy-related activity is detected in a run log.

Detection includes:
- Action references and action download SHAs
- APT package install patterns and version extraction
- Binary hashes observed in logs
- Known network IOC strings

Severity logic:
- **CRITICAL**: any IOC match (`ioc-hit`)
- **HIGH**: suspicious non-IOC risk pattern (for example `apt-0.69.4` or risky action ref)
- **MEDIUM**: baseline Trivy activity without IOC/high-risk trigger

## Report outputs explained

## `results.md`

Main investigation report with sections:

1. **Summary block**
   - Organization, time window, scan totals.
2. **Daily Summary**
   - Findings/day with type and severity counts.
3. **Findings table**
   - One row per detected run with evidence and rationale.
4. **All Scanned Runs**
   - Coverage view (which runs were scanned and whether Trivy was found).
5. **Flagged Items**
   - Quick list of CRITICAL/HIGH entries.

### Key Findings columns

- **Date (UTC)**: date portion for grouping/sorting.
- **Repository / Run**: direct links to repo and workflow run.
- **Run Time (UTC)**: normalized timestamp used in timeline analysis.
- **Workflow**: workflow/job name extracted from run metadata/logs.
- **Usage Type**: `action`, `apt`, `binary-download`, `container`, or `unknown`.
- **Trivy Details (Version + SHA)**:
  - action refs + resolved commit SHAs when available,
  - version hints from log evidence.
- **IOC Match**: matched IOC tokens (`workflow-sha:*`, `binary-sha256:*`, `network:*`).
- **Severity / Severity Trigger**:
  - severity grade and exact reason string (for analyst traceability).
- **Evidence Snippet**: normalized line snippets from logs used to support detection.

## `results.html`

Human-friendly interactive version of the report.

Notable capabilities:
- Includes all report sections from markdown output.
- Findings table supports in-header up/down sort controls (`▲`/`▼`) for:
  - `Date (UTC)`
  - `Run Time (UTC)`

## `logs/flags.txt`

Plain-text shortlist for rapid escalation workflows.
Each line includes severity, repository, run id, apt marker, and log path.

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

1. Update IOC DB files in `db/`.
2. Run live scan over incident window.
3. Review `results.html` sorted by run time/date.
4. Triage `CRITICAL` and `HIGH` first.
5. Use run links and evidence snippets to confirm context in GitHub.
6. Re-run in `--skip-run-listing` mode for fast iterative analysis.
