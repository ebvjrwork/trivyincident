import os
from typing import Set, Tuple


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
