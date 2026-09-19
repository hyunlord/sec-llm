"""Shared paths and helpers for P3."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
DATA = Path(os.environ.get("SEC_LLM_DATA_DIR") or (REPO / "data"))
INGESTED = DATA / "ingested"
PROCESSED = DATA / "processed"
OUT = DATA / "out"
MANIFESTS = REPO / "manifests"
REPORTS = REPO / "reports"
DOCS = REPO / "docs"
SCHEMAS = REPO / "datasets" / "schemas"

CVE_TABLE = OUT / "cve_table.jsonl"
ATTACK_TABLE = OUT / "attack_table.jsonl"

# Placeholder CWE values that carry no mapping information. Treated as absent.
CWE_PLACEHOLDERS = frozenset({"NVD-CWE-OTHER", "NVD-CWE-NOINFO", "CWE-NOINFO", "CWE-OTHER", "UNSURE"})


def ensure_dirs():
    for d in (OUT, MANIFESTS, REPORTS, DOCS, SCHEMAS):
        d.mkdir(parents=True, exist_ok=True)


def iter_jsonl(path: Path):
    with open(path, "r", encoding="utf-8") as fh:
        for line in fh:
            if line.strip():
                yield json.loads(line)


def write_jsonl(path: Path, rows) -> tuple[int, str]:
    """Write deterministically; return (count, sha256 of the file)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    h = hashlib.sha256()
    n = 0
    with open(tmp, "wb") as fh:
        for r in rows:
            b = (json.dumps(r, ensure_ascii=False, sort_keys=True) + "\n").encode("utf-8")
            fh.write(b)
            h.update(b)
            n += 1
    tmp.replace(path)
    return n, h.hexdigest()


def file_sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def stable_int(s: str, mod: int) -> int:
    """Deterministic, platform-independent bucket for a string."""
    return int(hashlib.sha256(s.encode("utf-8")).hexdigest()[:16], 16) % mod
