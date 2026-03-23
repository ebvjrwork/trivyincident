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
- Produces all output in the `results/` directory:
  - `results/results.html` — interactive HTML report with sort controls, exposure window highlighting, and severity badges
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
  - `indicators.py` – IOC DB loading.
  - `log_parser.py` – extraction, matching, severity logic.
  - `reporting.py` – HTML report and flags generation.
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

### `results/logs/*.html`

Per-finding annotated log views with:
- Evidence lines highlighted in red
- `trivy` keyword, version numbers, and action refs highlighted inline

### `logs/flags.txt`

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
3. Review `results/results.html` sorted by run time.
4. Triage `CRITICAL` and `HIGH` first.
5. Use run links and evidence snippets to confirm context in GitHub.
6. Re-run in `--skip-run-listing` mode for fast iterative analysis.
