#!/usr/bin/env python3
import argparse
import os
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from typing import Dict, List, Set, Tuple

from trivyincident.github_ops import (
    download_run_log,
    ensure_prereqs,
    get_rate_limit,
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
from trivyincident.reporting import write_flags_file, write_results_html, write_log_html


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
    parser.add_argument("--results-dir", default="results", help="Output directory for the HTML report and log HTMLs (default: results/)")
    parser.add_argument("--db-root", default="db")
    parser.add_argument("--include-archived", action="store_true")
    parser.add_argument("--max-repos", type=int, default=0)
    parser.add_argument(
        "--generate-log-html",
        action="store_true",
        help="Generate per-finding annotated HTML log files with evidence highlighted",
    )
    parser.add_argument(
        "--log-html-root",
        default="",
        help="Output directory for per-finding log HTML files (default: <results-dir>/logs/)",
    )
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

    # ── Phase 1: separate runs that need downloading from those already cached ──
    to_download: List[Tuple[RunInfo, str]] = []
    already_cached: List[Tuple[RunInfo, str]] = []

    for run in all_runs:
        repo_name = run.repo.split("/", 1)[1]
        out_path = os.path.join(args.logs_root, repo_name, f"{run.run_id}.log")
        if os.path.exists(out_path) and os.path.getsize(out_path) > 0:
            already_cached.append((run, out_path))
        else:
            to_download.append((run, out_path))

    skipped_existing = len(already_cached)
    print(
        f"logs: {skipped_existing} cached, {len(to_download)} to download",
        flush=True,
    )

    # ── Phase 2: download logs in parallel with rate-limit awareness ───────────
    if to_download:
        _lock = threading.Lock()
        _call_count = 0
        _RATE_CHECK_INTERVAL = 20
        _MIN_REMAINING = 100

        def _ensure_rate_limit() -> None:
            remaining, reset_ts = get_rate_limit()
            if remaining == -1:
                return  # couldn't check – proceed optimistically
            if remaining < _MIN_REMAINING:
                wait = max(reset_ts - time.time(), 0) + 1
                print(
                    f"  rate-limit low ({remaining} remaining), pausing {wait:.0f}s until reset",
                    flush=True,
                )
                time.sleep(wait)

        def _download_one(
            run: RunInfo, out_path: str, idx: int, total: int
        ) -> Tuple[RunInfo, str, bool, str]:
            nonlocal _call_count
            with _lock:
                _call_count += 1
                if _call_count % _RATE_CHECK_INTERVAL == 0:
                    _ensure_rate_limit()
            print(
                f"  [{idx}/{total}] downloading {run.repo} run {run.run_id}",
                flush=True,
            )
            ok, err, _ = download_run_log(run.repo, run.run_id, out_path)
            return run, out_path, ok, err

        # initial rate-limit check before starting
        _ensure_rate_limit()

        max_workers = min(5, len(to_download))
        total_dl = len(to_download)
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {
                executor.submit(_download_one, run, path, idx, total_dl): (run, path)
                for idx, (run, path) in enumerate(to_download, 1)
            }
            for future in as_completed(futures):
                run, out_path, ok, err = future.result()
                if ok:
                    downloaded += 1
                else:
                    failures.append(
                        {"repo": run.repo, "run_id": str(run.run_id), "error": err}
                    )

        print(
            f"  download phase done: {downloaded} succeeded, {len(failures)} failed",
            flush=True,
        )

    # ── Phase 3: parse all available logs ──────────────────────────────────────
    all_with_paths = already_cached + [
        (run, path) for run, path in to_download
        if os.path.exists(path) and os.path.getsize(path) > 0
    ]

    for run, out_path in all_with_paths:
        if not run.created_at:
            run.created_at = extract_first_log_timestamp_from_file(out_path)
        if not run.workflow_name:
            run.workflow_name = extract_workflow_name_from_file(out_path)

        finding = parse_log_for_finding(run, out_path)
        if finding:
            findings.append(finding)

    results_dir = args.results_dir.strip() or "results"
    html_report_path = os.path.join(results_dir, "results.html")

    # Optionally generate per-finding annotated log HTML files
    log_html_root: str = ""
    if args.generate_log_html:
        log_html_root = args.log_html_root.strip()
        if not log_html_root:
            log_html_root = os.path.join(results_dir, "logs")
        generated_log_htmls = 0
        for finding in findings:
            repo_name = finding.repository.split("/", 1)[1]
            out_html = os.path.join(log_html_root, repo_name, f"{finding.run_id}.html")
            write_log_html(finding.log_path, finding, out_html)
            generated_log_htmls += 1
        print(f"log htmls generated: {generated_log_htmls} files in {log_html_root}")

    write_results_html(
        output_path=html_report_path,
        org=args.org,
        run_start_iso=start_iso,
        run_end_iso=end_iso,
        repos_scanned=repos_scanned,
        total_runs=len(all_runs),
        downloaded=downloaded,
        skipped_existing=skipped_existing,
        failed=failures,
        findings=findings,
        all_runs=all_runs,
        log_html_root=log_html_root if args.generate_log_html else None,
    )

    flags_file = os.path.join(args.logs_root, "flags.txt")
    write_flags_file(flags_file, findings)

    print(
        f"completed: repos={repos_scanned} runs={len(all_runs)} downloaded_new={downloaded} "
        f"reused_existing={skipped_existing} findings={len(findings)}"
    )
    print(f"html report: {html_report_path}")
    print(f"flags: {flags_file}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
