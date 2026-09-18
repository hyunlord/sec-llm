"""Where ingested bytes live. None of it is committed."""

from __future__ import annotations

import os
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]

# Overridable so a gate test that deliberately induces a failure writes its run
# record somewhere the report renderer never reads. Sharing one store is how
# reports/ingest.md came to show cwe as both failed and successfully manifested.
DATA = Path(os.environ.get("SEC_LLM_DATA_DIR") or (REPO / "data"))
RAW = DATA / "raw"          # exactly what the source served
INGESTED = DATA / "ingested"  # lineage-wrapped records, JSONL, one file per source
STATE = DATA / "state"      # resume checkpoints
MANIFESTS = REPO / "manifests"

# Rule 3 carried over from P0.1: bound the download. A source that would exceed
# this stops and is recorded rather than filling the disk.
MAX_SOURCE_BYTES = 20 * 2**30  # 20 GiB


def ensure_dirs():
    for d in (RAW, INGESTED, STATE, MANIFESTS):
        d.mkdir(parents=True, exist_ok=True)


def check_size_bound(source_id: str, estimated_bytes: int) -> tuple[bool, str]:
    from .fetch import human_bytes

    if estimated_bytes > MAX_SOURCE_BYTES:
        return False, (
            f"{source_id}: estimated {human_bytes(estimated_bytes)} exceeds the "
            f"{human_bytes(MAX_SOURCE_BYTES)} bound; refusing to fetch"
        )
    return True, f"{source_id}: estimated {human_bytes(estimated_bytes)}, within the {human_bytes(MAX_SOURCE_BYTES)} bound"
