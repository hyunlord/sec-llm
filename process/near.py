"""Stage 4 -- near duplicates via MinHash + LSH.

Determinism is a requirement, not a nicety: re-running must produce identical
cluster assignments. That means a fixed seed, fixed permutations, sorted
iteration at every point where order could leak into the result, and a
union-find whose representative is chosen by sorted key rather than by whichever
record happened to arrive first.

Two decisions worth stating because the opposite is tempting:

  * Run per content type, never globally. Comparing a STIX relationship object
    to a CVE description is meaningless, and mixing them saturates LSH buckets
    with garbage that slows everything down and finds nothing.

  * Do NOT strip security entities before shingling. Removing CVE identifiers,
    product names and version strings is the obvious-looking optimization and it
    is wrong here: vulnerability descriptions are formulaic enough that "a
    buffer overflow in X version Y allows remote attackers to execute arbitrary
    code" collapses across hundreds of unrelated CVEs once the entities are
    gone. The entities are what distinguishes them.

Implemented on stdlib only -- no datasketch dependency, and no source builds.
"""

from __future__ import annotations

import hashlib
import json
import random
import struct

import numpy as np
import sys
import time
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from process.common import INDEX_PATH, iter_jsonl, peak_rss_bytes  # noqa: E402

SEED = 1234
NUM_PERM = 128
SHINGLE_SIZE = 5          # word-level 5-grams
MERSENNE_PRIME = (1 << 61) - 1
MAX_HASH = (1 << 32) - 1
MIN_TOKENS = 8            # below this a text is too short for shingling to mean anything


def _permutations(num_perm: int, seed: int):
    """Fixed random permutations. Same seed -> same permutations, always."""
    rng = random.Random(seed)
    return [
        (rng.randint(1, MERSENNE_PRIME - 1), rng.randint(0, MERSENNE_PRIME - 1))
        for _ in range(num_perm)
    ]


PERMS = _permutations(NUM_PERM, SEED)


def shingles(text: str, k: int = SHINGLE_SIZE) -> set[bytes]:
    """Word-level k-shingles. Security entities are kept, by design."""
    toks = text.split()
    if len(toks) < MIN_TOKENS:
        return set()
    if len(toks) < k:
        return {" ".join(toks).encode("utf-8")}
    return {" ".join(toks[i : i + k]).encode("utf-8") for i in range(len(toks) - k + 1)}


# Permutation coefficients as arrays so the whole signature is one vectorized
# op per record instead of NUM_PERM Python-level multiplications per shingle.
# Pure Python here was ~2.3 billion interpreted operations over this corpus.
_A = np.array([a for a, _ in PERMS], dtype=np.uint64)
_B = np.array([b for _, b in PERMS], dtype=np.uint64)


def minhash(sh: set[bytes]) -> tuple[int, ...] | None:
    if not sh:
        return None
    hv = np.fromiter(
        (struct.unpack("<I", hashlib.sha1(x).digest()[:4])[0] for x in sorted(sh)),
        dtype=np.uint64,
        count=len(sh),
    )
    # (n_shingles, num_perm) -> min over shingles
    v = ((_A[None, :] * hv[:, None] + _B[None, :]) % MERSENNE_PRIME) & np.uint64(MAX_HASH)
    return tuple(int(x) for x in v.min(axis=0))


def _bands_rows(threshold: float, num_perm: int = NUM_PERM) -> tuple[int, int]:
    """Pick (bands, rows) whose LSH S-curve best matches the threshold.

    The standard optimisation: minimise the sum of false-positive and
    false-negative area under the (1 - (1 - s^r)^b) curve.
    """
    best, best_err = (num_perm, 1), float("inf")
    for b in range(1, num_perm + 1):
        if num_perm % b:
            continue
        r = num_perm // b
        # Probability of becoming a candidate at exactly the threshold.
        fp = 1 - (1 - threshold ** r) ** b
        err = abs(fp - 0.5)
        if err < best_err:
            best, best_err = (b, r), err
    return best


def jaccard(a: set[bytes], b: set[bytes]) -> float:
    if not a or not b:
        return 0.0
    inter = len(a & b)
    return inter / (len(a) + len(b) - inter)


class UnionFind:
    def __init__(self):
        self.parent: dict[str, str] = {}

    def find(self, x: str) -> str:
        self.parent.setdefault(x, x)
        root = x
        while self.parent[root] != root:
            root = self.parent[root]
        while self.parent[x] != root:
            self.parent[x], x = root, self.parent[x]
        return root

    def union(self, a: str, b: str) -> None:
        ra, rb = self.find(a), self.find(b)
        if ra == rb:
            return
        # Deterministic: the lexicographically smaller root always wins, so the
        # result does not depend on the order edges were discovered.
        lo, hi = (ra, rb) if ra < rb else (rb, ra)
        self.parent[hi] = lo


def load_content_type(content_type: str) -> list[dict]:
    rows = []
    for r in iter_jsonl(INDEX_PATH):
        if r["content_type"] != content_type or not r["text_len"]:
            continue
        rows.append(
            {"key": f"{r['source_id']}:{r['record_id']}",
             "source_id": r["source_id"], "record_id": r["record_id"], "text": r["text"]}
        )
    rows.sort(key=lambda x: x["key"])
    return rows


def generate_candidates(rows: list[dict], band_threshold: float = 0.72, verbose=True) -> dict:
    """Hash once and produce candidate pairs with their exact Jaccard.

    Banding is tuned to the LOWEST threshold in the calibration sweep, not to
    each threshold in turn. Every threshold then filters the same candidate
    pool, which is both far cheaper (one hashing pass instead of four) and the
    only way the sweep's precision and recall are comparable across thresholds --
    otherwise each row of the table would be measured against a different
    candidate set.
    """
    t0 = time.time()
    bands, rows_per_band = _bands_rows(band_threshold)

    sigs: dict[str, tuple] = {}
    shs: dict[str, set[bytes]] = {}
    for rec in rows:
        sh = shingles(rec["text"])
        if not sh:
            continue
        sig = minhash(sh)
        if sig is None:
            continue
        shs[rec["key"]] = sh
        sigs[rec["key"]] = sig

    buckets: dict[tuple, list[str]] = defaultdict(list)
    for key in sorted(sigs):
        sig = sigs[key]
        for b in range(bands):
            buckets[(b, sig[b * rows_per_band : (b + 1) * rows_per_band])].append(key)

    pairs: dict[tuple[str, str], float] = {}
    comparisons = 0
    saturated = 0
    for bkey in sorted(buckets, key=lambda k: (k[0], k[1])):
        members = sorted(buckets[bkey])
        if len(members) < 2:
            continue
        # A bucket that has collapsed into hundreds of members is noise: it costs
        # O(n^2) to compare and the pairs inside it are near-identical boilerplate.
        if len(members) > 300:
            saturated += 1
            continue
        for i in range(len(members)):
            for j in range(i + 1, len(members)):
                key = (members[i], members[j])
                if key in pairs:
                    continue
                pairs[key] = jaccard(shs[key[0]], shs[key[1]])
                comparisons += 1

    if verbose:
        print(f"    {len(sigs):,} hashed, bands={bands}x{rows_per_band}, "
              f"{comparisons:,} pairs scored, {saturated} saturated buckets skipped "
              f"({time.time()-t0:.1f}s)", flush=True)
    return {
        "pairs": pairs,
        "keys": sorted(sigs),
        "hashed": len(sigs),
        "bands": bands,
        "rows_per_band": rows_per_band,
        "comparisons": comparisons,
        "saturated_buckets_skipped": saturated,
        "elapsed_seconds": round(time.time() - t0, 1),
    }


def cluster_from_pairs(keys: list[str], pairs: dict, threshold: float) -> dict[str, list[str]]:
    """Union-find over the candidate pairs at or above `threshold`."""
    uf = UnionFind()
    for (a, b) in sorted(pairs):
        if pairs[(a, b)] >= threshold:
            uf.union(a, b)
    clusters: dict[str, list[str]] = defaultdict(list)
    for k in sorted(keys):
        root = uf.find(k) if k in uf.parent else k
        clusters[root].append(k)
    return {root: sorted(m) for root, m in clusters.items() if len(m) > 1}


def build_candidate_pools(content_types: list[str] | None = None, verbose=True) -> dict:
    """One hashing pass over the corpus; reused by every threshold."""
    by_type: dict[str, int] = defaultdict(int)
    for r in iter_jsonl(INDEX_PATH):
        by_type[r["content_type"]] += 1
    types = sorted(content_types or by_type)

    pools = {}
    for ct in types:
        rows = load_content_type(ct)
        if len(rows) < 2:
            continue
        if verbose:
            print(f"  {ct}: {len(rows):,} records", flush=True)
        pools[ct] = generate_candidates(rows, verbose=verbose)
        pools[ct]["records"] = len(rows)
    return pools


def run(threshold: float, pools: dict | None = None, content_types: list[str] | None = None) -> dict:
    t0 = time.time()
    if pools is None:
        pools = build_candidate_pools(content_types)

    decisions: dict[tuple[str, str], dict] = {}
    stats: dict[str, dict] = {}

    for ct in sorted(pools):
        pool = pools[ct]
        clusters = cluster_from_pairs(pool["keys"], pool["pairs"], threshold)
        marked = 0
        for root, members in sorted(clusters.items()):
            cid = f"near:{ct}:{hashlib.sha256(root.encode()).hexdigest()[:16]}"
            rep = members[0]
            for k in members:
                sid, rid = k.split(":", 1)
                is_rep = k == rep
                pk = (rep, k) if rep < k else (k, rep)
                sim = 1.0 if is_rep else float(pool["pairs"].get(pk, threshold))
                decisions[(sid, rid)] = {
                    "dedup_cluster_id": cid,
                    "dedup_stage": "near",
                    "dedup_role": "representative" if is_rep else "member",
                    "dedup_keep": is_rep,
                    "dedup_reason": (
                        f"near-duplicate cluster at Jaccard>={threshold} within "
                        f"content_type={ct}; "
                        + ("kept as representative" if is_rep else f"similar to {rep}")
                    ),
                    "dedup_similarity": round(sim, 4),
                }
                if not is_rep:
                    marked += 1
        stats[ct] = {
            "records": pool["records"],
            "hashed": pool["hashed"],
            "candidate_pairs": pool["comparisons"],
            "clusters": len(clusters),
            "records_marked_near_duplicate": marked,
            "bands": pool["bands"],
            "rows_per_band": pool["rows_per_band"],
            "saturated_buckets_skipped": pool["saturated_buckets_skipped"],
        }

    return {
        "threshold": threshold,
        "decisions": decisions,
        "by_content_type": stats,
        "total_marked": sum(s["records_marked_near_duplicate"] for s in stats.values()),
        "total_clusters": sum(s["clusters"] for s in stats.values()),
        "elapsed_seconds": round(time.time() - t0, 1),
        "peak_rss_bytes": peak_rss_bytes(),
        "params": {"seed": SEED, "num_perm": NUM_PERM, "shingle_size": SHINGLE_SIZE,
                   "min_tokens": MIN_TOKENS, "max_bucket_size": 300,
                   "band_threshold": 0.72},
    }


if __name__ == "__main__":
    th = float(sys.argv[1]) if len(sys.argv) > 1 else 0.85
    out = run(th)
    print(json.dumps({k: v for k, v in out.items() if k not in ("decisions", "pairs")}, indent=2))
