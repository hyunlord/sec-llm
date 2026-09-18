"""`make process` -- run every P2 stage and emit the manifest and reports.

Nothing is deleted. Every one of the 823,285 records survives with an added
decision, so the removal rate stays auditable, every judgement stays reversible,
and changing the threshold does not mean re-running the pipeline. Physical
removal belongs to P3, when a dataset is actually materialized.
"""

from __future__ import annotations

import json
import pickle
import sys
import time
from collections import Counter, defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import process.near as near  # noqa: E402
from process import calibrate, exact, identity, secrets  # noqa: E402
from process.common import (  # noqa: E402
    DECISIONS_PATH,
    INDEX_PATH,
    MANIFESTS,
    PROCESSED,
    ensure_dirs,
    iter_jsonl,
    peak_rss_bytes,
    write_jsonl,
)

CHOSEN_THRESHOLD = 0.75
CHOSEN_RATIONALE = (
    "Precision is flat within its 95% bootstrap interval across all four tested "
    "thresholds while recall nearly triples from 0.90 to 0.75, so the higher "
    "thresholds buy no measurable precision and pay for it in redundancy left behind."
)
POOLS_PATH = PROCESSED / "candidate_pools.pkl"


def main() -> int:
    ensure_dirs()
    t0 = time.time()
    stages: dict[str, dict] = {}

    print("=" * 70 + "\nSTAGE 1 -- canonicalization\n" + "=" * 70, flush=True)
    stages["canonical"] = exact.build_index()
    print(f"  {stages['canonical']['records_indexed']:,} records indexed "
          f"({stages['canonical']['elapsed_seconds']}s)")

    print("\n" + "=" * 70 + "\nSTAGE 2 -- exact duplicates\n" + "=" * 70, flush=True)
    ex = exact.find_exact()
    stages["exact"] = ex["stats"]
    print(f"  {ex['stats']['exact_clusters']:,} clusters, "
          f"{ex['stats']['records_marked_duplicate']:,} records marked")

    print("\n" + "=" * 70 + "\nSTAGE 3 -- identity grouping (NOT deduplication)\n" + "=" * 70, flush=True)
    ident = identity.build_entities()
    stages["identity"] = {k: v for k, v in ident.items() if k != "cwe_conflict_examples"}
    print(f"  {ident['entities']:,} entities, {ident['entities_in_multiple_sources']:,} in >1 source, "
          f"{ident['entities_with_field_conflicts']:,} with field conflicts")

    print("\n" + "=" * 70 + "\nSTAGE 4 -- near duplicates\n" + "=" * 70, flush=True)
    if POOLS_PATH.exists():
        print("  reusing the candidate pool on disk (hashing is deterministic; "
              "the pool is a function of the index)")
        with open(POOLS_PATH, "rb") as f:
            pools = pickle.load(f)
    else:
        pools = near.build_candidate_pools()
        with open(POOLS_PATH, "wb") as f:
            pickle.dump(pools, f)
    nr = near.run(CHOSEN_THRESHOLD, pools=pools)
    stages["near"] = {k: v for k, v in nr.items() if k != "decisions"}
    print(f"  threshold {CHOSEN_THRESHOLD}: {nr['total_clusters']:,} clusters, "
          f"{nr['total_marked']:,} records marked")

    print("\n" + "=" * 70 + "\nCALIBRATION\n" + "=" * 70, flush=True)
    pairs = [json.loads(l) for l in open(calibrate.PAIRS_PATH)]
    table = calibrate.sweep(pairs, pools=pools)
    stages["calibration"] = {
        "table": table,
        "labelled_pairs": len(pairs),
        "chosen_threshold": CHOSEN_THRESHOLD,
        "rationale": CHOSEN_RATIONALE,
        "annotation": pairs[0].get("annotation") if pairs else None,
        "limits": [
            "Recall is measured against labelled CANDIDATE pairs at or above 0.70. "
            "Pairs LSH never proposed cannot appear in the denominator, so this is not "
            "recall against all truly redundant pairs in the corpus.",
            "The label set is imbalanced (206 redundant / 4 not), so the precision "
            "confidence intervals are wide at the lower bound and the sample cannot "
            "discriminate between thresholds on precision.",
            "The annotator is a language model, not a human security analyst.",
        ],
    }
    for m in table:
        print(f"  th={m['threshold']:.2f} clusters={m['clusters']:>6,} "
              f"marked={m['records_marked_near_duplicate']:>7,} "
              f"P={m['precision']:.3f} R={m['recall']:.3f} F1={m['f1']:.3f}")

    print("\n" + "=" * 70 + "\nSTAGE 5 -- secrets and PII\n" + "=" * 70, flush=True)
    stages["secrets"] = secrets.scan_corpus()
    print(f"  {stages['secrets']['findings_total']:,} findings "
          f"({stages['secrets']['findings_by_category']})")

    # ---- merge decisions; nothing is deleted -----------------------------
    print("\n" + "=" * 70 + "\nDECISIONS\n" + "=" * 70, flush=True)
    decisions = dict(ex["decisions"])
    for key, d in nr["decisions"].items():
        # An exact duplicate is already the stronger finding; do not downgrade it.
        if key not in decisions:
            decisions[key] = d

    entity_sources: dict[str, list] = {}
    for row in iter_jsonl(identity.ENTITY_PATH):
        if len(row["sources"]) > 1:
            entity_sources[row["entity_id"]] = row["sources"]

    rows = []
    stage_counts = Counter()
    keep_counts = Counter()
    per_source = defaultdict(Counter)
    per_type = defaultdict(Counter)
    total = 0

    for row in iter_jsonl(INDEX_PATH):
        key = (row["source_id"], row["record_id"])
        d = decisions.get(key)
        if d is None:
            eid = row.get("entity_id")
            if eid and eid in entity_sources:
                d = {
                    "dedup_cluster_id": f"identity:{eid}",
                    "dedup_stage": "identity",
                    "dedup_role": "member",
                    "dedup_keep": True,
                    "dedup_reason": (
                        f"entity {eid} appears in {entity_sources[eid]}; these are two sources "
                        "describing one entity, not duplicates -- both are kept and the "
                        "disagreement between them is recorded in the entity view"
                    ),
                    "dedup_similarity": None,
                }
            else:
                d = {
                    "dedup_cluster_id": f"unique:{row['canonical_sha256'][:16]}",
                    "dedup_stage": "unique",
                    "dedup_role": "representative",
                    "dedup_keep": True,
                    "dedup_reason": "no exact or near duplicate found",
                    "dedup_similarity": None,
                }
        out = {
            "source_id": row["source_id"],
            "record_id": row["record_id"],
            "entity_id": row["entity_id"],
            "content_type": row["content_type"],
            "canonical_sha256": row["canonical_sha256"],
            "transform_history": [
                {"stage": "canonical", "transforms": row["transforms_applied"]},
                {"stage": d["dedup_stage"], "cluster": d["dedup_cluster_id"]},
            ],
            **d,
        }
        rows.append(out)
        stage_counts[d["dedup_stage"]] += 1
        keep_counts[bool(d["dedup_keep"])] += 1
        per_source[row["source_id"]][d["dedup_stage"]] += 1
        per_type[row["content_type"]][d["dedup_stage"]] += 1
        total += 1

    rows.sort(key=lambda r: (r["source_id"], r["record_id"]))
    n = write_jsonl(DECISIONS_PATH, rows)
    print(f"  {n:,} decisions written -> {DECISIONS_PATH}")

    marked_for_removal = keep_counts[False]
    summary = {
        "records_in": stages["canonical"]["records_indexed"],
        "records_out": n,
        "records_deleted": 0,
        "decisions_by_stage": dict(stage_counts),
        "records_kept": keep_counts[True],
        "records_marked_not_kept": marked_for_removal,
        "removal_rate": round(marked_for_removal / n, 6) if n else 0.0,
        "by_source": {s: dict(c) for s, c in sorted(per_source.items())},
        "by_content_type": {s: dict(c) for s, c in sorted(per_type.items())},
    }

    manifest = {
        "schema_version": 1,
        "phase": "P2",
        "chosen_near_duplicate_threshold": CHOSEN_THRESHOLD,
        "threshold_rationale": CHOSEN_RATIONALE,
        "summary": summary,
        "stages": stages,
        "determinism": (
            "Fixed MinHash seed and permutations, sorted iteration at every point where "
            "order could leak into the result, and a union-find whose representative is "
            "the lexicographically smallest key. No wall-clock field is recorded here, so "
            "re-running against the same index reproduces this file byte for byte."
        ),
        "policy": (
            "P2 marks; it does not delete. Every input record appears in the output with "
            "a decision attached. Physical removal happens in P3 when a dataset is "
            "materialized."
        ),
    }
    # Strip wall-clock/memory readings: they belong in the report, not in a file
    # that has to reproduce byte for byte.
    for st in manifest["stages"].values():
        if isinstance(st, dict):
            st.pop("elapsed_seconds", None)
            st.pop("peak_rss_bytes", None)

    out_path = MANIFESTS / "process.manifest.json"
    out_path.write_bytes(
        json.dumps(manifest, indent=2, sort_keys=True, ensure_ascii=False).encode("utf-8") + b"\n"
    )
    print(f"  manifest -> {out_path}")

    runtime = {
        "total_wall_seconds": round(time.time() - t0, 1),
        "peak_rss_bytes": peak_rss_bytes(),
        "stage_seconds": {
            "canonical": stages["canonical"].get("elapsed_seconds"),
            "identity": ident.get("elapsed_seconds"),
            "near": nr.get("elapsed_seconds"),
            "secrets": stages["secrets"].get("elapsed_seconds"),
        },
    }
    (PROCESSED / "process_run.json").write_text(json.dumps(runtime, indent=2) + "\n")

    print(f"\nrecords in {summary['records_in']:,} -> out {summary['records_out']:,}, "
          f"deleted {summary['records_deleted']}, marked-not-kept {marked_for_removal:,} "
          f"({summary['removal_rate']:.2%})")
    print(f"total wall {runtime['total_wall_seconds']}s")
    return 0


if __name__ == "__main__":
    sys.exit(main())
