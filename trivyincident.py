#!/usr/bin/env python3
import argparse
import os
import sys
from datetime import datetime, timezone
from typing import Dict, List, Set, Tuple

from trivyincident.github_ops import (
    download_run_log,
    ensure_prereqs,
    list_repos,
    list_runs_in_window,
)
from trivyincident.indicators import load_indicator_sets
from trivyincident.log_parser import (
    extract_first_log_timestamp_from_file,
    extract_workflow_name_from_file,
    parse_log_for_finding,
    set_indicator_sets,
)
from trivyincident.models import Finding, RunInfo
from trivyincident.reporting import write_flags_file, write_results_html, write_results_md


def to_iso_utc(value: str) -> str:
    dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def list_local_log_runs(logs_root: str, org: str) -> Tuple[List[RunInfo], int]:
    runs: List[RunInfo] = []
    repos: Set[str] = set()
    if not os.path.isdir(logs_root):
        return runs, 0

    for repo_name in sorted(os.listdir(logs_root)):
        repo_path = os.path.join(logs_root, repo_name)
        if not os.path.isdir(repo_path):
            continue
        repos.add(repo_name)
        for entry in sorted(os.listdir(repo_path)):
            if not entry.endswith(".log"):
                continue
            stem = entry[:-4]
            if not stem.isdigit():
                continue
            run_id = int(stem)
            runs.append(
                RunInfo(
                    repo=f"{org}/{repo_name}",
                    run_id=run_id,
                    run_number=0,
                    created_at="",
                    workflow_name="",
                    conclusion="",
                    status="",
                )
            )

    runs.sort(key=lambda item: (item.repo, item.run_id))
    return runs, len(repos)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--org", required=True)
    parser.add_argument("--start", required=True, help="UTC ISO time, example 2026-03-19T00:00:00Z")
    parser.add_argument("--end", required=True, help="UTC ISO time, example 2026-03-21T20:00:00Z")
    parser.add_argument("--logs-root", default="logs")
    parser.add_argument("--report", default="results.md")
    parser.add_argument("--html-report", default="")
    parser.add_argument("--db-root", default="db")
    parser.add_argument("--include-archived", action="store_true")
    parser.add_argument("--max-repos", type=int, default=0)
    parser.add_argument(
        "--skip-run-listing",
        action="store_true",
        help="Scan existing logs in --logs-root and skip GitHub repository/run listing",
    )
    args = parser.parse_args()

    workflow_iocs, binary_iocs, network_iocs = load_indicator_sets(args.db_root)
    set_indicator_sets(workflow_iocs, binary_iocs, network_iocs)

    start_iso = to_iso_utc(args.start)
    end_iso = to_iso_utc(args.end)

    os.makedirs(args.logs_root, exist_ok=True)

    all_runs: List[RunInfo] = []
    repos_scanned = 0
    if args.skip_run_listing:
        all_runs, repos_scanned = list_local_log_runs(args.logs_root, args.org)
        print(
            f"skip-run-listing enabled: discovered {len(all_runs)} local logs across {repos_scanned} repositories",
            flush=True,
        )
    else:
        ensure_prereqs()
        repos = list_repos(args.org, args.include_archived)
        if args.max_repos > 0:
            repos = repos[: args.max_repos]
        repos_scanned = len(repos)

        for idx, repo in enumerate(repos, start=1):
            print(f"[{idx}/{len(repos)}] listing runs for {repo.full_name}", flush=True)
            try:
                runs = list_runs_in_window(repo.full_name, start_iso, end_iso)
            except Exception as exc:
                print(f"run listing failed for {repo.full_name}: {exc}", file=sys.stderr, flush=True)
                continue
            all_runs.extend(runs)

    findings: List[Finding] = []
    failures: List[Dict[str, str]] = []
    downloaded = 0
    skipped_existing = 0

    for idx, run in enumerate(all_runs, start=1):
        repo_name = run.repo.split("/", 1)[1]
        out_path = os.path.join(args.logs_root, repo_name, f"{run.run_id}.log")
        if os.path.exists(out_path) and os.path.getsize(out_path) > 0:
            skipped_existing += 1
            print(f"[{idx}/{len(all_runs)}] skipping existing log {out_path}", flush=True)
        else:
            print(f"[{idx}/{len(all_runs)}] downloading {run.repo} run {run.run_id}", flush=True)
            ok, err, _ = download_run_log(run.repo, run.run_id, out_path)
            if not ok:
                failures.append({"repo": run.repo, "run_id": str(run.run_id), "error": err})
                continue
            downloaded += 1

        if not run.created_at:
            run.created_at = extract_first_log_timestamp_from_file(out_path)
        if not run.workflow_name:
            run.workflow_name = extract_workflow_name_from_file(out_path)

        finding = parse_log_for_finding(run, out_path)
        if finding:
            findings.append(finding)

    write_results_md(
        output_path=args.report,
        org=args.org,
        start_iso=start_iso,
        end_iso=end_iso,
        repos_scanned=repos_scanned,
        total_runs=len(all_runs),
        downloaded=downloaded,
        skipped_existing=skipped_existing,
        failed=failures,
        findings=findings,
        all_runs=all_runs,
    )

    html_report_path = args.html_report.strip() if args.html_report else ""
    if not html_report_path:
        base, _ = os.path.splitext(args.report)
        html_report_path = f"{base}.html"

    write_results_html(
        output_path=html_report_path,
        org=args.org,
        start_iso=start_iso,
        end_iso=end_iso,
        repos_scanned=repos_scanned,
        total_runs=len(all_runs),
        downloaded=downloaded,
        skipped_existing=skipped_existing,
        failed=failures,
        findings=findings,
        all_runs=all_runs,
    )

    flags_file = os.path.join(args.logs_root, "flags.txt")
    write_flags_file(flags_file, findings)

    print(
        f"completed: repos={repos_scanned} runs={len(all_runs)} downloaded_new={downloaded} "
        f"reused_existing={skipped_existing} findings={len(findings)}"
    )
    print(f"report: {args.report}")
    print(f"html report: {html_report_path}")
    print(f"flags: {flags_file}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
