"""Contamination criteria (library) and their rendering (CLI).

Ownership, per docs/engineering-rules.md rule 1: build.py APPLIES these criteria
and writes the removal record into the manifest. This module computes the
criteria when build.py asks, renders the recorded result on --render, and on
--assert-zero performs a RE-CHECK that is labelled as such and written to a
separate file. It never overwrites the record of what was removed.

Why the criterion changed. The temporal split already guarantees no CVE is in
both training and evaluation, so an eval description sharing one 13-token span
with a training description means two CNAs wrote the same template, not that a
document leaked. Zero-tolerance on a single 13-gram removed 28-61% of the eval
sets and biased what survived toward vendors who do not use templates. The real
residual risk is a near-copy of a training input under a different CVE id --
which is exactly what P2's MinHash detects. So:

  applied   near-duplicate input   Jaccard >= NEAR_THRESHOLD against any training text,
                                   P2's shingling / seed / permutations, imported not reimplemented
  applied   coverage ratio         fraction of the item's 13-grams present anywhere in training
                                   > COVERAGE_MAX (an independent second criterion)
  diagnostic  any-13-gram          the old criterion, reported, NOT applied
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from datasets import temporal  # noqa: E402
from datasets.common import MANIFESTS, OUT, REPORTS, iter_jsonl  # noqa: E402
from process import near as p2near  # noqa: E402  -- P2's MinHash, same seed/shingles

TASKS = ("cve_to_cwe", "cvss_vector", "attack_technique", "structured_extract")
EVAL_SPLITS = (temporal.EVAL_POST, temporal.EVAL_PRE)
POLICY_N = 13
DIAG_N = 8
# P2 adopted 0.75 from the calibration table. P2.1 was to revisit it and has not
# been delivered, so P2's value stands and is recorded as such.
NEAR_THRESHOLD = 0.75
NEAR_THRESHOLD_SOURCE = "P2 calibration (P2.1 not delivered)"
COVERAGE_MAX = 0.5
CANDIDATE_CAP = 3000
BAND_THRESHOLD = 0.72  # same permissive banding P2 used for candidate generation


def _h(s: str) -> int:
    return int.from_bytes(hashlib.blake2b(s.encode("utf-8"), digest_size=8).digest(), "little")


def ngrams(text: str, n: int):
    toks = text.split()
    for i in range(len(toks) - n + 1):
        yield " ".join(toks[i:i + n])


# ---------------------------------------------------------------- n-gram index
def ngram_index(texts, n: int) -> np.ndarray:
    chunks, buf = [], []
    for text in texts:
        for g in ngrams(text, n):
            buf.append(_h(g))
        if len(buf) >= 2_000_000:
            chunks.append(np.unique(np.fromiter(buf, dtype=np.uint64, count=len(buf)))); buf = []
    if buf:
        chunks.append(np.unique(np.fromiter(buf, dtype=np.uint64, count=len(buf))))
    return np.unique(np.concatenate(chunks)) if chunks else np.array([], dtype=np.uint64)


def coverage(text: str, idx: np.ndarray, n: int) -> dict:
    grams = list(ngrams(text, n))
    if not grams or idx.size == 0:
        return {"fraction": 0.0, "n_grams": len(grams), "n_hit": 0, "example_gram": None}
    hs = np.fromiter((_h(g) for g in grams), dtype=np.uint64, count=len(grams))
    pos = np.searchsorted(idx, hs); pos[pos >= idx.size] = 0
    hit = idx[pos] == hs
    n_hit = int(hit.sum())
    ex = next((g for g, f in zip(grams, hit) if f), None)
    return {"fraction": round(n_hit / len(grams), 4), "n_grams": len(grams), "n_hit": n_hit, "example_gram": ex}


# ------------------------------------------------------------ near-dup index
class NearIndex:
    """LSH over training texts using P2's shingles/minhash/banding, so that an
    eval text can be matched against training the way P2 matched train against
    itself. Orchestration only; every hash and comparison is p2near's."""

    def __init__(self, items):
        self.bands, self.rows = p2near._bands_rows(BAND_THRESHOLD)
        self.shingles: dict[str, set] = {}
        self.buckets: dict[tuple, list[str]] = defaultdict(list)
        for key, text in items:
            sh = p2near.shingles(text)
            if not sh:
                continue
            sig = p2near.minhash(sh)
            if sig is None:
                continue
            self.shingles[key] = sh
            for b in range(self.bands):
                self.buckets[(b, sig[b * self.rows:(b + 1) * self.rows])].append(key)
        self.size = len(self.shingles)

    def nearest(self, text: str) -> dict:
        sh = p2near.shingles(text)
        if not sh:
            return {"key": None, "jaccard": 0.0, "candidates": 0, "capped": False}
        sig = p2near.minhash(sh)
        cands: set[str] = set()
        for b in range(self.bands):
            cands.update(self.buckets.get((b, sig[b * self.rows:(b + 1) * self.rows]), ()))
        capped = len(cands) > CANDIDATE_CAP
        best_k, best_j = None, 0.0
        for k in sorted(cands)[:CANDIDATE_CAP]:
            j = p2near.jaccard(sh, self.shingles[k])
            if j > best_j:
                best_k, best_j = k, j
        return {"key": best_k, "jaccard": round(best_j, 4), "candidates": len(cands), "capped": capped}


# ------------------------------------------------------------------- screening
def screen(eval_texts: dict[str, str], train_texts: list[tuple[str, str]]) -> tuple[dict, dict]:
    """eval_texts: {eval_key: input text}; train_texts: [(train_key, text), ...].
    Returns (per_eval_key_verdict, index_stats). Deterministic."""
    idx13 = ngram_index((t for _, t in train_texts), POLICY_N)
    idx8 = ngram_index((t for _, t in train_texts), DIAG_N)
    near = NearIndex(train_texts)
    out = {}
    for key in sorted(eval_texts):
        text = eval_texts[key]
        cov = coverage(text, idx13, POLICY_N)
        cov8 = coverage(text, idx8, DIAG_N)
        nn = near.nearest(text)
        criteria = []
        if nn["jaccard"] >= NEAR_THRESHOLD:
            criteria.append("near_duplicate")
        if cov["fraction"] > COVERAGE_MAX:
            criteria.append("coverage")
        out[key] = {
            "removed": bool(criteria), "criteria": criteria,
            "near_match": nn, "coverage_13": cov, "coverage_8_fraction": cov8["fraction"],
            "diag_any_13gram": cov["n_hit"] > 0, "diag_any_8gram": cov8["n_hit"] > 0,
        }
    stats = {"train_unique_13grams": int(idx13.size), "train_unique_8grams": int(idx8.size),
             "train_texts_hashed_for_near_dup": near.size, "near_threshold": NEAR_THRESHOLD,
             "near_threshold_source": NEAR_THRESHOLD_SOURCE, "coverage_max": COVERAGE_MAX,
             "minhash_params": {"seed": p2near.SEED, "num_perm": p2near.NUM_PERM,
                                "shingle_size": p2near.SHINGLE_SIZE, "bands": near.bands, "rows": near.rows}}
    return out, stats


def hist(values, edges):
    c = Counter()
    for v in values:
        for lo, hi in zip(edges, edges[1:]):
            if lo <= v < hi or (v == edges[-1] and hi == edges[-1]):
                c[f"[{lo},{hi})"] += 1; break
    return dict(c)


def tvd(p: Counter, q: Counter) -> float:
    """Total variation distance between two CNA distributions."""
    keys = set(p) | set(q)
    sp, sq = sum(p.values()) or 1, sum(q.values()) or 1
    return round(0.5 * sum(abs(p[k] / sp - q[k] / sq) for k in keys), 4)


# ---------------------------------------------------------------------- render
def render(manifest: dict) -> Path:
    c = manifest["contamination"]
    L = ["# P3.1 오염 검사 보고서\n",
         "> `manifests/datasets.manifest.json`의 **기록된 제거 사실**을 렌더링한다. 여기서 아무것도 다시 계산하지 않는다 "
         "(`docs/engineering-rules.md` 규칙 1). `make datasets-docs` 또는 `python -m datasets.contamination --render`.\n"]
    L.append("## 기준이 바뀐 이유\n")
    L.append("시간 분할이 이미 같은 CVE가 학습과 평가에 동시에 있을 수 없음을 보장한다. 그러므로 평가 설명문이 학습 설명문과 "
             "13토큰 연쇄 하나를 공유한다는 것은 **두 CNA가 같은 템플릿으로 썼다**는 뜻이지 문서가 샜다는 뜻이 아니다. "
             "P3의 단일 13-gram 무관용은 평가 세트의 28–61%를 제거했고, 살아남은 항목은 템플릿을 쓰지 않는 벤더 쪽으로 기울었으며, "
             "공정 비교가 목적인 컷오프 이전 세트는 반토막이 났다.\n")
    L.append("실제로 남는 위험은 **다른 CVE ID를 단 학습 입력의 근사 복사본**이다. 벤더는 권고문 사이에서 설명을 복사한다. "
             "그것은 근접 중복 입력이고, P2의 MinHash가 탐지하는 바로 그것이다.\n")
    s = c["index"]
    L.append("## 적용된 기준\n")
    L.append(f"1. **근접 중복 입력** — Jaccard ≥ **{s['near_threshold']}** (출처: {s['near_threshold_source']}). "
             f"P2의 `process/near.py`를 import (seed {s['minhash_params']['seed']}, 순열 {s['minhash_params']['num_perm']}, "
             f"{s['minhash_params']['shingle_size']}-gram 셰일, 밴드 {s['minhash_params']['bands']}×{s['minhash_params']['rows']}). 재구현하지 않았다.")
    L.append(f"2. **커버리지 비율** — 항목의 13-gram 중 학습 어딘가에 존재하는 비율 > **{s['coverage_max']}**. 독립된 두 번째 기준.")
    L.append(f"3. *(진단만)* 단일 13-gram 일치 — 옛 기준. **보고하되 적용하지 않는다.**\n")
    L.append(f"학습 측 인덱스: 고유 13-gram {s['train_unique_13grams']:,}, 8-gram {s['train_unique_8grams']:,}, "
             f"근접 중복용 해시 텍스트 {s['train_texts_hashed_for_near_dup']:,} (학습 4과제 입력+정답, 리플레이 프롬프트+응답).\n")
    L.append("## 평가 세트별 실제 제거 (build.py가 수행하고 기록한 값)\n")
    L.append("| 평가 세트 | 검사 전 | 근접중복 | 커버리지 | 둘 다 | **제거 합계** | 제거율 | 검사 후 | *(진단)* 단일13-gram 옛 기준이면 |")
    L.append("|---|---|---|---|---|---|---|---|---|")
    for k, v in c["eval_sets"].items():
        L.append(f"| `{k}` | {v['before']:,} | {v['removed_by_near_only']:,} | {v['removed_by_coverage_only']:,} | {v['removed_by_both']:,} | "
                 f"**{v['removed']:,}** | {v['removed_fraction']:.1%} | {v['after']:,} | {v['diag_old_criterion_would_remove']:,} ({v['diag_old_criterion_fraction']:.1%}) |")
    L.append(f"\n총 제거 **{c['total_removed']:,}건**. 옛 기준이었다면 **{c['total_diag_old_criterion']:,}건**.\n")
    L.append("## 분포\n\n**커버리지 비율(13-gram) 분포** — 평가 항목 전체:\n")
    L.append("| 구간 | 항목 수 |\n|---|---|")
    for k, v in c["coverage_histogram"].items():
        L.append(f"| `{k}` | {v:,} |")
    L.append("\n**최근접 학습 항목과의 Jaccard 분포**:\n\n| 구간 | 항목 수 |\n|---|---|")
    for k, v in c["near_jaccard_histogram"].items():
        L.append(f"| `{k}` | {v:,} |")
    L.append("\n## CNA 분포 — 옛 기준 vs 새 기준 vs 학습 세트\n")
    L.append("TVD = 학습 세트 CNA 분포와의 총변동거리 (0 = 동일, 1 = 완전히 다름). 새 기준 아래 값이 옛 기준보다 학습에 가까우면 편향이 줄어든 것이다.\n")
    L.append("| 평가 세트 | 검사 전 TVD | 옛 기준 후 TVD | **새 기준 후 TVD** | 상위 CNA (새 기준 후) |\n|---|---|---|---|---|")
    for k, v in c["cna_distribution"].items():
        top = ", ".join(f"{a} {n}" for a, n in v["after_new_top"][:5])
        L.append(f"| `{k}` | {v['tvd_before']} | {v['tvd_after_old']} | **{v['tvd_after_new']}** | {top} |")
    # Verdict sentence is formatting over the recorded TVDs, not a new computation.
    d = c["cna_distribution"]
    closer = [k for k, v in d.items() if v["tvd_after_new"] < v["tvd_after_old"]]
    still = [k for k, v in d.items() if v["tvd_after_new"] > v["tvd_before"] + 0.02]
    L.append(f"\n**판정**: {len(d)}개 CVE 평가 세트 중 **{len(closer)}개**에서 새 기준 후 CNA 분포가 옛 기준 후보다 학습 분포에 더 가깝다"
             + (f"; 검사 전보다 학습에서 눈에 띄게 멀어진 세트는 {still}이다 — 남은 편향은 여기다." if still else
                "; 어떤 세트도 검사 전보다 학습 분포에서 눈에 띄게(TVD +0.02 초과) 멀어지지 않았다.") + "\n")
    L.append("## 제거된 항목 — 전부 검사 가능\n")
    L.append(f"제거된 {c['total_removed']:,}건 각각의 ID·기준·최근접 학습 항목·커버리지가 매니페스트 `removal_record`에 있다. 처음 몇 건:\n")
    L.append("| 예제 | 기준 | 최근접 학습 항목 | Jaccard | 커버리지 | 일치 13-gram 예 |\n|---|---|---|---|---|---|")
    for r in manifest["removal_record"][:12]:
        L.append(f"| `{r['example_id']}` | {','.join(r['criteria'])} | `{r['near_match']['key']}` | {r['near_match']['jaccard']} | "
                 f"{r['coverage_13']['fraction']} | `{(r['coverage_13']['example_gram'] or '')[:60]}` |")
    L.append("\n## 교차 평가 검사\n")
    for k, v in c["cross_eval"].items():
        L.append(f"- `{k}`: {v} (0이어야 함)")
    rc = OUT / "contamination_recheck.json"
    if rc.exists():
        r = json.loads(rc.read_text())
        L.append(f"\n## RE-CHECK (별도 파일, 제거 기록이 아님)\n\n`--assert-zero`가 최종 파일을 다시 검사한 결과: "
                 f"기준 초과 항목 **{r['items_exceeding_criteria']}건** ({'통과' if r['items_exceeding_criteria']==0 else '실패'}). "
                 "이 숫자는 재검증이며 위의 제거 건수와 별개다.")
    out = REPORTS / "contamination.md"
    out.write_text("\n".join(L) + "\n", encoding="utf-8")
    return out


# --------------------------------------------------------------------- re-check
def recheck() -> int:
    """RE-CHECK: recompute both applied criteria on the final files. Writes to
    contamination_recheck.json, never to the removal record."""
    train = []
    for t in TASKS + ("replay",):
        p = OUT / t / f"{temporal.TRAIN}.jsonl"
        if p.exists():
            for ex in iter_jsonl(p):
                train.append((f"{t}:{ex['entity_id']}:in", ex.get("input") or ""))
                if ex.get("target_json"):
                    train.append((f"{t}:{ex['entity_id']}:tg", ex["target_json"]))
    evals = {}
    for t in TASKS:
        for sp in EVAL_SPLITS:
            p = OUT / t / f"{sp}.jsonl"
            if p.exists():
                for ex in iter_jsonl(p):
                    evals[f"{t}/{sp}:{ex['entity_id']}"] = ex.get("input") or ""
    verdicts, stats = screen(evals, train)
    bad = [k for k, v in verdicts.items() if v["removed"]]
    rep = {"label": "RE-CHECK -- this is a re-verification of the final files, not the removal record",
           "items_checked": len(evals), "items_exceeding_criteria": len(bad), "examples": bad[:20], "index": stats}
    (OUT / "contamination_recheck.json").write_text(json.dumps(rep, indent=2, ensure_ascii=False) + "\n")
    print(f"RE-CHECK: {len(evals):,} eval items re-screened; {len(bad)} exceed the applied criteria")
    return 1 if bad else 0


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--render", action="store_true", help="render the recorded removal from the manifest")
    ap.add_argument("--assert-zero", action="store_true", help="RE-CHECK final files; labelled as such")
    a = ap.parse_args()
    if a.render:
        print(render(json.loads((MANIFESTS / "datasets.manifest.json").read_text())))
    if a.assert_zero:
        sys.exit(recheck())
    if not (a.render or a.assert_zero):
        ap.print_help()
