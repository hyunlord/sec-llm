"""Recompute the Cond-2 ⊂ Cond-1 relation from the PUBLISHED FILES.

Not from the manifest's claim about them. The manifest records the digests the
build computed; this reads the files on this machine, recomputes the digests,
checks the subset relation directly, and only then compares with the record.
Run at training start; a failure stops the run before a single step.
"""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))

from eval.common import OUT, MANIFESTS, iter_jsonl  # noqa: E402

SCORED = ("cve_to_cwe", "cvss_vector", "structured_extract")


def ids_sha(ids) -> str:
    return hashlib.sha256("\n".join(sorted(ids)).encode("utf-8")).hexdigest()


def verify() -> dict:
    ids1, ids2 = set(), set()
    for t in SCORED:
        ids1.update(e["example_id"] for e in iter_jsonl(OUT / t / "train_subsample.jsonl"))
        ids2.update(e["example_id"] for e in iter_jsonl(OUT / t / "train_cond2_domain.jsonl"))
    extra = sorted(ids2 - ids1)
    inter = ids1 & ids2
    h1, h2, hi = ids_sha(ids1), ids_sha(ids2), ids_sha(inter)
    rec = json.loads((MANIFESTS / "datasets.manifest.json").read_text())["decisions"]["conditions"]["subset_proof"]
    out = {
        "cond1_ids": len(ids1), "cond2_domain_ids": len(ids2),
        "cond2_not_in_cond1": len(extra),
        "subset_holds": not extra and h2 == hi,
        "cond1_ids_sha256": h1, "cond2_domain_ids_sha256": h2, "intersection_sha256": hi,
        "matches_manifest_record": (rec["cond1_ids_sha256"] == h1 and rec["cond2_domain_ids_sha256"] == h2),
        "source": "recomputed from data/out/*/train_subsample.jsonl and train_cond2_domain.jsonl on this host",
    }
    return out


def main() -> int:
    r = verify()
    print(json.dumps(r, indent=2))
    ok = r["subset_holds"] and r["matches_manifest_record"]
    print("SUBSET VERIFIED FROM FILES" if ok else "SUBSET CHECK FAILED")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
