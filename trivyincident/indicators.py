import os
import sys
import urllib.request
import urllib.error
from typing import Set, Tuple

_DB_BASE_URL = "https://raw.githubusercontent.com/ebvjrwork/trivyincident/refs/heads/main/db"

_DB_FILES = [
    "binary-sha256.db",
    "network-ioc.db",
    "workflow-sha.db",
]


def update_indicator_dbs(db_root: str) -> None:
    """Download the latest indicator DB files from the upstream repo."""
    os.makedirs(db_root, exist_ok=True)
    for name in _DB_FILES:
        url = f"{_DB_BASE_URL}/{name}"
        dest = os.path.join(db_root, name)
        try:
            req = urllib.request.Request(url, method="GET")
            with urllib.request.urlopen(req, timeout=15) as resp:
                data = resp.read()
            with open(dest, "wb") as f:
                f.write(data)
            print(f"  updated {dest} ({len(data)} bytes) from {url}", flush=True)
        except (urllib.error.URLError, OSError) as exc:
            print(
                f"  warning: failed to update {dest} from {url}: {exc}",
                file=sys.stderr,
                flush=True,
            )


def load_indicator_db_file(path: str) -> Set[str]:
    values: Set[str] = set()
    if not os.path.exists(path):
        return values
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for raw in f:
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            values.add(line.lower())
    return values


def load_indicator_sets(db_root: str) -> Tuple[Set[str], Set[str], Set[str]]:
    workflow = load_indicator_db_file(os.path.join(db_root, "workflow-sha.db"))
    if not workflow:
        workflow = load_indicator_db_file(os.path.join(db_root, "workflow_shas.db"))

    binary = load_indicator_db_file(os.path.join(db_root, "binary-sha256.db"))
    if not binary:
        binary = load_indicator_db_file(os.path.join(db_root, "binary_sha256.db"))

    network = load_indicator_db_file(os.path.join(db_root, "network-ioc.db"))
    if not network:
        network = load_indicator_db_file(os.path.join(db_root, "network_iocs.db"))

    return workflow, binary, network
