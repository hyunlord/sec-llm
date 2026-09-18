"""Shared paths and helpers for the P2 processing stages."""

from __future__ import annotations

import json
import os
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
DATA = Path(os.environ.get("SEC_LLM_DATA_DIR") or (REPO / "data"))
INGESTED = DATA / "ingested"
PROCESSED = DATA / "processed"
LABELS = REPO / "data" / "labels"
MANIFESTS = REPO / "manifests"
REPORTS = REPO / "reports"

INDEX_PATH = PROCESSED / "index.jsonl"
DECISIONS_PATH = PROCESSED / "decisions.jsonl"
ENTITY_PATH = PROCESSED / "entities.jsonl"

SOURCES = ["cve_list", "nvd", "cwe", "attack"]


def ensure_dirs():
    for d in (PROCESSED, LABELS, MANIFESTS, REPORTS):
        d.mkdir(parents=True, exist_ok=True)


def iter_jsonl(path: Path):
    with open(path, "r", encoding="utf-8") as fh:
        for line in fh:
            if line.strip():
                yield json.loads(line)


def write_jsonl(path: Path, rows) -> int:
    path.parent.mkdir(parents=True, exist_ok=True)
    n = 0
    tmp = path.with_suffix(path.suffix + ".tmp")
    with open(tmp, "w", encoding="utf-8") as fh:
        for r in rows:
            fh.write(json.dumps(r, ensure_ascii=False, sort_keys=True) + "\n")
            n += 1
    tmp.replace(path)
    return n


def human(n) -> str:
    n = float(n or 0)
    for u in ("B", "KiB", "MiB", "GiB", "TiB"):
        if abs(n) < 1024 or u == "TiB":
            return f"{n:.1f} {u}"
        n /= 1024
    return f"{n:.1f} TiB"


def peak_rss_bytes() -> int:
    """Peak resident set size of this process, in bytes.

    resource.ru_maxrss is bytes on macOS and kilobytes on Linux; this code runs
    on both, so normalise rather than report a number that is wrong by 1024x on
    one of them.
    """
    import resource
    import sys

    v = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    return v if sys.platform == "darwin" else v * 1024
