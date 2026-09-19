"""n-gram overlap between every evaluation set and the full training set.

Policy: 13-gram, zero tolerance -- any eval item sharing a 13-gram with any
training item (domain or replay) is removed and counted. 8-gram is run as a
diagnostic on the same sets and reported alongside; the difference between the
two is a measurement of how formulaic the corpus is.

The training index holds n-grams from every training item's `input` AND its
`target_json` (hashed as two separate texts, so no gram straddles the boundary).
The evaluation side is checked on `input` ONLY. Targets are structured labels
from a small vocabulary -- a CVSS object has a few thousand possible values --
so every eval target shares long spans with training targets by construction;
hashing them on the eval side removed 4,567 of 4,578 cvss_vector items and
measured the size of the label space, not memorization. The instruction
template is never hashed on either side: it is shared by design.

Hashes are 64-bit and held in sorted numpy arrays, so ~50M training n-grams
cost ~400 MB rather than the several GB a Python set would.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from collections import Counter
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from datasets import temporal  # noqa: E402
from datasets.common import OUT, iter_jsonl, write_jsonl  # noqa: E402

TASKS = ("cve_to_cwe", "cvss_vector", "attack_technique", "structured_extract")
EVAL_SPLITS = (temporal.EVAL_POST, temporal.EVAL_PRE)
POLICY_N = 13
DIAG_N = 8
MASK = (1 << 64) - 1


def _h(s: str) -> int:
    return int.from_bytes(hashlib.blake2b(s.encode("utf-8"), digest_size=8).digest(), "little")


def ngrams(text: str, n: int):
    toks = text.split()
    for i in range(len(toks) - n + 1):
        yield " ".join(toks[i:i + n])


def train_texts(ex: dict):
    """Both sides of a training item, as separate texts."""
    yield ex.get("input", "") or ""
    yield ex.get("target_json", "") or ""


def eval_text(ex: dict) -> str:
    """Only the input is the memorization surface; see module docstring."""
    return ex.get("input", "") or ""


def train_index(n: int) -> np.ndarray:
    chunks = []
    buf = []
    for t in TASKS + ("replay",):
        p = OUT / t / f"{temporal.TRAIN}.jsonl"
        if not p.exists():
            continue
        for ex in iter_jsonl(p):
            for text in train_texts(ex):
                for g in ngrams(text, n):
                    buf.append(_h(g))
            if len(buf) >= 2_000_000:
                chunks.append(np.unique(np.fromiter(buf, dtype=np.uint64, count=len(buf))))
                buf = []
    if buf:
        chunks.append(np.unique(np.fromiter(buf, dtype=np.uint64, count=len(buf))))
    if not chunks:
        return np.array([], dtype=np.uint64)
    return np.unique(np.concatenate(chunks))


def flagged(ex: dict, idx: np.ndarray, n: int) -> list[str]:
    """Membership against the sorted index via searchsorted.

    np.isin re-sorts its second argument on every call; against a 60M-entry
    index, called once per eval example per n, that is hours of work. The index
    from np.unique is already sorted, so a binary search is the right tool and
    each example costs microseconds.
    """
    grams = list(ngrams(eval_text(ex), n))
    if not grams or idx.size == 0:
        return []
    hs = np.fromiter((_h(g) for g in grams), dtype=np.uint64, count=len(grams))
    pos = np.searchsorted(idx, hs)
    pos[pos >= idx.size] = 0
    hit = idx[pos] == hs
    return [g for g, f in zip(grams, hit) if f]


def run(assert_zero: bool = False) -> int:
    print(f"building {POLICY_N}-gram and {DIAG_N}-gram training indexes...", flush=True)
    idx13 = train_index(POLICY_N)
    idx8 = train_index(DIAG_N)
    print(f"  train {POLICY_N}-grams: {idx13.size:,} unique | {DIAG_N}-grams: {idx8.size:,} unique", flush=True)

    report = {"policy_n": POLICY_N, "diagnostic_n": DIAG_N,
              "train_unique_ngrams": {str(POLICY_N): int(idx13.size), str(DIAG_N): int(idx8.size)},
              "eval_sets": {}, "cross_eval": {}, "top_diag_grams": {}}
    any_removed = 0
    ids_by_split: dict[str, dict[str, set]] = {}

    for t in TASKS:
        for sp in EVAL_SPLITS:
            p = OUT / t / f"{sp}.jsonl"
            if not p.exists():
                continue
            rows = list(iter_jsonl(p))
            keep, removed13, would8, extra8 = [], 0, 0, 0
            diag_counter = Counter()
            for ex in rows:
                f13 = flagged(ex, idx13, POLICY_N)
                f8 = flagged(ex, idx8, DIAG_N)
                if f8:
                    would8 += 1
                    for g in f8[:3]:
                        diag_counter[g] += 1
                if f13:
                    removed13 += 1
                else:
                    if f8:
                        extra8 += 1
                    keep.append(ex)
            n_after = len(keep)
            if removed13 or assert_zero is False:
                write_jsonl(p, keep)
            any_removed += removed13
            ids_by_split.setdefault(t, {})[sp] = {e["entity_id"] for e in keep}
            report["eval_sets"][f"{t}/{sp}"] = {
                "before": len(rows), "removed_at_13": removed13, "after": n_after,
                "removed_fraction_13": round(removed13 / len(rows), 4) if rows else 0.0,
                "would_remove_at_8": would8,
                "additional_at_8_beyond_13": extra8,
                "would_remove_fraction_8": round(would8 / len(rows), 4) if rows else 0.0,
            }
            report["top_diag_grams"][f"{t}/{sp}"] = diag_counter.most_common(8)
            print(f"  {t:18} {sp:16} before={len(rows):5} removed@13={removed13:5} "
                  f"after={n_after:5} would@8={would8:5} (+{extra8} beyond 13)", flush=True)

    # cross-eval: the same entity in both temporal sets is a construction bug
    for t, d in ids_by_split.items():
        a, b = d.get(temporal.EVAL_POST, set()), d.get(temporal.EVAL_PRE, set())
        report["cross_eval"][t] = {"shared_entity_ids": len(a & b)}
        assert not (a & b), f"{t}: {len(a & b)} entities in both temporal eval sets"
    # and across tasks: a CVE must carry one split label everywhere
    post_all = set().union(*(d.get(temporal.EVAL_POST, set()) for t, d in ids_by_split.items() if t != "attack_technique"))
    pre_all = set().union(*(d.get(temporal.EVAL_PRE, set()) for t, d in ids_by_split.items() if t != "attack_technique"))
    report["cross_eval"]["cve_tasks_post_vs_pre_shared"] = len(post_all & pre_all)
    assert not (post_all & pre_all), "a CVE is post-cutoff in one task and pre-cutoff in another"

    report["total_removed_at_13"] = any_removed
    (OUT / "contamination.json").write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n")

    if assert_zero:
        if any_removed:
            print(f"ASSERTION FAILED: {any_removed} eval items still overlap the training set at {POLICY_N}-gram")
            return 1
        print(f"OK: zero {POLICY_N}-gram overlap between every eval set and the training set")
    return 0


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--assert-zero", action="store_true", help="fail if any 13-gram overlap remains")
    a = ap.parse_args()
    sys.exit(run(assert_zero=a.assert_zero))
