"""Threshold calibration: sweep, sample, label, measure.

A threshold taken from a paper is an assertion. A threshold chosen from a
labelled sample, with the precision and recall of the decision reported, is a
measurement. This file produces the second thing.

The sample is stratified by similarity band -- pairs just below the candidate
thresholds, just above, and well above -- because a sample drawn uniformly from
2.46 million candidate pairs would be almost entirely low-similarity noise and
would say nothing about where the decision boundary should sit.
"""

from __future__ import annotations

import json
import pickle
import random
import sys
from collections import Counter, defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from process.common import INDEX_PATH, LABELS, PROCESSED, iter_jsonl  # noqa: E402

POOLS_PATH = PROCESSED / "candidate_pools.pkl"
PAIRS_PATH = LABELS / "near_dup_pairs.jsonl"

THRESHOLDS = [0.75, 0.80, 0.85, 0.90]
SAMPLE_SEED = 20260918

# Bands straddle every threshold under test so each one has pairs just above and
# just below it in the labelled set.
BANDS = [
    (0.70, 0.75), (0.75, 0.80), (0.80, 0.85),
    (0.85, 0.90), (0.90, 0.95), (0.95, 1.001),
]
PER_BAND = 35
TEXT_TRUNC = 320


def load_pools() -> dict:
    with open(POOLS_PATH, "rb") as f:
        return pickle.load(f)


def sample_pairs() -> list[dict]:
    pools = load_pools()
    texts: dict[str, str] = {}
    wanted: set[str] = set()

    banded: dict[tuple, list] = defaultdict(list)
    for ct in sorted(pools):
        for (a, b), sim in sorted(pools[ct]["pairs"].items()):
            for lo, hi in BANDS:
                if lo <= sim < hi:
                    banded[(lo, hi)].append((ct, a, b, sim))
                    break

    rng = random.Random(SAMPLE_SEED)
    chosen = []
    for band in BANDS:
        rows = banded.get(band, [])
        rows.sort()  # deterministic before sampling
        pick = rows if len(rows) <= PER_BAND else rng.sample(rows, PER_BAND)
        for ct, a, b, sim in sorted(pick):
            chosen.append({"content_type": ct, "a": a, "b": b,
                           "similarity": round(float(sim), 4),
                           "band": f"[{band[0]:.2f},{band[1]:.2f})"})
            wanted.update((a, b))

    for row in iter_jsonl(INDEX_PATH):
        k = f"{row['source_id']}:{row['record_id']}"
        if k in wanted:
            texts[k] = row["text"][:TEXT_TRUNC]

    for c in chosen:
        c["text_a"] = texts.get(c["a"], "")
        c["text_b"] = texts.get(c["b"], "")
        c["label"] = None
    return chosen


def metrics(pairs: list[dict], threshold: float) -> dict:
    """Precision/recall of 'mark as near-duplicate at >= threshold' vs the labels."""
    tp = fp = fn = tn = 0
    for p in pairs:
        if p.get("label") is None:
            continue
        pred = p["similarity"] >= threshold
        truth = bool(p["label"])
        if pred and truth:
            tp += 1
        elif pred and not truth:
            fp += 1
        elif not pred and truth:
            fn += 1
        else:
            tn += 1
    prec = tp / (tp + fp) if (tp + fp) else float("nan")
    rec = tp / (tp + fn) if (tp + fn) else float("nan")
    f1 = 2 * prec * rec / (prec + rec) if (tp and (prec + rec)) else float("nan")
    return {"threshold": threshold, "tp": tp, "fp": fp, "fn": fn, "tn": tn,
            "precision": prec, "recall": rec, "f1": f1,
            "labelled": tp + fp + fn + tn}


def bootstrap_ci(pairs: list[dict], threshold: float, n: int = 2000, seed: int = 7) -> dict:
    """Percentile bootstrap CIs. The sample is ~200 pairs; point estimates alone
    would imply more precision than that supports."""
    labelled = [p for p in pairs if p.get("label") is not None]
    if not labelled:
        return {}
    rng = random.Random(seed)
    precs, recs = [], []
    for _ in range(n):
        boot = [labelled[rng.randrange(len(labelled))] for _ in range(len(labelled))]
        m = metrics(boot, threshold)
        if m["tp"] + m["fp"]:
            precs.append(m["precision"])
        if m["tp"] + m["fn"]:
            recs.append(m["recall"])
    def ci(v):
        if not v:
            return (float("nan"), float("nan"))
        v = sorted(v)
        return (v[int(0.025 * len(v))], v[min(len(v) - 1, int(0.975 * len(v)))])
    return {"precision_ci95": ci(precs), "recall_ci95": ci(recs), "bootstrap_n": n}


def sweep(pairs: list[dict], pools: dict | None = None) -> list[dict]:
    pools = pools if pools is not None else load_pools()
    import process.near as near

    out = []
    for t in THRESHOLDS:
        m = metrics(pairs, t)
        m.update(bootstrap_ci(pairs, t))
        clusters = marked = 0
        for ct in sorted(pools):
            cl = near.cluster_from_pairs(pools[ct]["keys"], pools[ct]["pairs"], t)
            clusters += len(cl)
            marked += sum(len(v) - 1 for v in cl.values())
        m["clusters"] = clusters
        m["records_marked_near_duplicate"] = marked
        out.append(m)
    return out


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--sample":
        rows = sample_pairs()
        PAIRS_PATH.parent.mkdir(parents=True, exist_ok=True)
        with open(PAIRS_PATH, "w", encoding="utf-8") as f:
            for r in rows:
                f.write(json.dumps(r, ensure_ascii=False, sort_keys=True) + "\n")
        print(f"wrote {len(rows)} pairs -> {PAIRS_PATH}")
        print("band distribution:", dict(Counter(r["band"] for r in rows)))
    else:
        pairs = [json.loads(l) for l in open(PAIRS_PATH)]
        for m in sweep(pairs):
            print(json.dumps(m))
