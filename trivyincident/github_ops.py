import io
import json
import os
import shlex
import subprocess
import time
import zipfile
from typing import List, Optional, Tuple

from .models import RepoInfo, RunInfo


def get_rate_limit() -> Tuple[int, float]:
    """Return (remaining_requests, reset_unix_timestamp) for the core GitHub API.

    Returns (-1, 0.0) if the rate limit could not be fetched.
    """
    try:
        result = subprocess.run(
            ["gh", "api", "rate_limit"],
            text=True, capture_output=True, check=False,
        )
        if result.returncode != 0:
            return -1, 0.0
        data = json.loads(result.stdout)
        core = data.get("resources", {}).get("core", {})
        return core.get("remaining", 0), float(core.get("reset", 0))
    except Exception:
        return -1, 0.0


def run_cmd(cmd: List[str], capture: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, text=True, capture_output=capture, check=False)


def run_gh_json(args: List[str]) -> object:
    cmd = ["gh"] + args
    result = run_cmd(cmd)
    if result.returncode != 0:
        raise RuntimeError(f"Command failed: {' '.join(shlex.quote(x) for x in cmd)}\n{result.stderr.strip()}")
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"Invalid JSON output from: {' '.join(cmd)}") from exc


def ensure_prereqs() -> None:
    gh_check = run_cmd(["gh", "--version"])
    if gh_check.returncode != 0:
        raise RuntimeError("gh CLI is not available")
    auth = run_cmd(["gh", "auth", "status"])
    if auth.returncode != 0:
        raise RuntimeError("gh auth is not configured. Run: gh auth login")


def list_repos(org: str, include_archived: bool) -> List[RepoInfo]:
    repos_json = run_gh_json(["repo", "list", org, "--limit", "2000", "--json", "name,nameWithOwner,isArchived"])
    repos: List[RepoInfo] = []
    for item in repos_json:
        if item.get("isArchived") and not include_archived:
            continue
        repos.append(RepoInfo(name=item["name"], full_name=item["nameWithOwner"]))
    repos.sort(key=lambda r: r.full_name.lower())
    return repos


def list_runs_in_window(repo_full_name: str, start_iso: str, end_iso: str) -> List[RunInfo]:
    runs: List[RunInfo] = []
    page = 1
    total_count: Optional[int] = None
    while True:
        data = run_gh_json(
            [
                "api",
                f"repos/{repo_full_name}/actions/runs",
                "--method",
                "GET",
                "-f",
                "per_page=100",
                "-f",
                f"page={page}",
                "-f",
                f"created={start_iso}..{end_iso}",
            ]
        )
        if total_count is None:
            try:
                total_count = int(data.get("total_count", 0))
            except Exception:
                total_count = 0
        page_runs = data.get("workflow_runs", [])
        if not page_runs:
            break
        for run in page_runs:
            runs.append(
                RunInfo(
                    repo=repo_full_name,
                    run_id=run["id"],
                    run_number=run.get("run_number", 0),
                    created_at=run.get("created_at", ""),
                    workflow_name=run.get("name") or "",
                    conclusion=run.get("conclusion") or "",
                    status=run.get("status") or "",
                )
            )
        if total_count and len(runs) >= total_count:
            break
        page += 1
    runs.sort(key=lambda r: r.created_at)
    return runs


def download_run_log(repo_full_name: str, run_id: int, output_path: str, retries: int = 3) -> Tuple[bool, str, int]:
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    for attempt in range(1, retries + 1):
        cmd = ["gh", "run", "view", str(run_id), "-R", repo_full_name, "--log"]
        result = run_cmd(cmd)
        if result.returncode == 0 and result.stdout:
            with open(output_path, "w", encoding="utf-8") as f:
                f.write(result.stdout)
            return True, "", len(result.stdout.encode("utf-8"))

        api_cmd = ["gh", "api", f"repos/{repo_full_name}/actions/runs/{run_id}/logs"]
        api_result = subprocess.run(api_cmd, capture_output=True, check=False)
        if api_result.returncode == 0 and api_result.stdout:
            try:
                with zipfile.ZipFile(io.BytesIO(api_result.stdout)) as zip_file:
                    parts: List[str] = []
                    for name in sorted(zip_file.namelist()):
                        if name.endswith("/"):
                            continue
                        data = zip_file.read(name)
                        text = data.decode("utf-8", errors="replace")
                        parts.append(f"===== {name} =====\n{text}")
                    merged = "\n\n".join(parts)
                if merged.strip():
                    with open(output_path, "w", encoding="utf-8") as f:
                        f.write(merged)
                    return True, "", len(merged.encode("utf-8"))
            except zipfile.BadZipFile:
                pass

        err_parts = []
        if result.stderr.strip():
            err_parts.append(result.stderr.strip())
        if api_result.stderr:
            try:
                api_err = api_result.stderr.decode("utf-8", errors="replace").strip()
            except Exception:
                api_err = ""
            if api_err:
                err_parts.append(api_err)
        err = " | ".join(err_parts) if err_parts else "empty log output"
        if attempt < retries:
            time.sleep(attempt * 2)
            continue
        return False, err, 0
    return False, "unknown error", 0
