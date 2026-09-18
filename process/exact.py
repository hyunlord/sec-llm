"""Stage 1+2 -- build the canonical index, then find exact duplicates.

One streaming pass over the ingested JSONL produces the index every later stage
reads: canonical text, its SHA-256, and the identifying fields. Streaming
because the two largest sources are 2 GB and 2.4 GB of JSONL and holding them
in memory would be a needless constraint on a stage that does not require it.

Exact duplicates are grouped by (content_type, canonical_sha256). Within a
content type only -- a CVE record and an NVD record for the same CVE are
different content types and are handled by stage 3, which treats them as one
entity rather than as duplicates.
"""

from __future__ import annotations

import hashlib
import json
import sys
import time
from collections import Counter, defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from process.canonical import TRANSFORMS, canonicalize  # noqa: E402
from process.common import (  # noqa: E402
    INDEX_PATH,
    INGESTED,
    SOURCES,
    ensure_dirs,
    human,
    iter_jsonl,
    peak_rss_bytes,
)
from process.textract import extract  # noqa: E402


def build_index() -> dict:
    ensure_dirs()
    t0 = time.time()
    transform_counts: dict[str, Counter] = defaultdict(Counter)
    per_source = Counter()
    per_type = Counter()
    empty_text = Counter()
    total = 0

    tmp = INDEX_PATH.with_suffix(".tmp")
    with open(tmp, "w", encoding="utf-8") as out:
        for sid in SOURCES:
            path = INGESTED / f"{sid}.jsonl"
            if not path.exists():
                print(f"  {sid}: no ingested file; skipping")
                continue
            n = 0
            for rec in iter_jsonl(path):
                lin = rec["lineage"]
                ct = lin["content_type"]
                ex = extract(ct, rec["content"])
                canon, applied = canonicalize(ex["text"])
                for a in applied:
                    transform_counts[sid][a] += 1
                if not canon:
                    empty_text[sid] += 1
                row = {
                    "source_id": sid,
                    "record_id": lin["record_id"],
                    "entity_id": lin["entity_id"],
                    "content_type": ct,
                    "canonical_sha256": hashlib.sha256(canon.encode("utf-8")).hexdigest(),
                    "text_len": len(canon),
                    "transforms_applied": applied,
                    "text": canon,
                }
                out.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")
                per_source[sid] += 1
                per_type[ct] += 1
                n += 1
                total += 1
                if n % 100_000 == 0:
                    print(f"    {sid}: {n:,} ({time.time()-t0:.0f}s)", flush=True)
            print(f"  {sid}: {n:,} records indexed")
    tmp.replace(INDEX_PATH)

    return {
        "records_indexed": total,
        "per_source": dict(per_source),
        "per_content_type": dict(per_type),
        "records_with_empty_text": dict(empty_text),
        "transforms_applied_counts": {s: dict(c) for s, c in sorted(transform_counts.items())},
        "transform_names": list(TRANSFORMS),
        "index_bytes": INDEX_PATH.stat().st_size,
        "elapsed_seconds": round(time.time() - t0, 1),
        "peak_rss_bytes": peak_rss_bytes(),
    }


def find_exact() -> dict:
    """Group by (content_type, canonical_sha256); first record_id is representative.

    Records with empty canonical text are excluded: every one of them hashes to
    the SHA-256 of the empty string, so grouping them would produce one enormous
    bogus cluster that says nothing about redundancy.
    """
    t0 = time.time()
    groups: dict[tuple[str, str], list[tuple[str, str]]] = defaultdict(list)
    empty_hash = hashlib.sha256(b"").hexdigest()
    skipped_empty = 0

    for row in iter_jsonl(INDEX_PATH):
        if row["canonical_sha256"] == empty_hash or not row["text_len"]:
            skipped_empty += 1
            continue
        groups[(row["content_type"], row["canonical_sha256"])].append(
            (row["source_id"], row["record_id"])
        )

    decisions: dict[tuple[str, str], dict] = {}
    dup_groups = 0
    dup_members = 0
    per_type = Counter()
    for (ct, sha), members in groups.items():
        if len(members) < 2:
            continue
        dup_groups += 1
        members.sort()  # deterministic representative
        rep = members[0]
        cluster = f"exact:{ct}:{sha[:16]}"
        for i, (sid, rid) in enumerate(members):
            is_rep = i == 0
            decisions[(sid, rid)] = {
                "dedup_cluster_id": cluster,
                "dedup_stage": "exact",
                "dedup_role": "representative" if is_rep else "member",
                "dedup_keep": is_rep,
                "dedup_reason": (
                    f"exact duplicate: identical canonical text within content_type={ct}; "
                    + ("kept as cluster representative" if is_rep
                       else f"identical to {rep[0]}:{rep[1]}")
                ),
                "dedup_similarity": 1.0,
            }
            if not is_rep:
                dup_members += 1
                per_type[ct] += 1

    return {
        "decisions": decisions,
        "stats": {
            "exact_clusters": dup_groups,
            "records_marked_duplicate": dup_members,
            "records_skipped_empty_text": skipped_empty,
            "duplicates_by_content_type": dict(per_type),
            "elapsed_seconds": round(time.time() - t0, 1),
            "peak_rss_bytes": peak_rss_bytes(),
        },
    }


if __name__ == "__main__":
    info = build_index()
    print(json.dumps(info, indent=2)[:2000])
