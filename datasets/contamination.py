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
which is exactly what P2's MinHash detects.

P3.2 then removed the second criterion. Coverage > 0.5 was a threshold specified
without evidence -- the same defect this project objected to in P2's borrowed
0.85. It removed 2,483 items whose coverage ran p25 0.581 / median 0.667, a dense
band that is Linux kernel CVEs and templated vendors, and the recorded CNA
distributions showed the cost: two evaluation sets ended up FURTHER from the
training distribution than before any filtering. That is not bias removed, it is
bias substituted. Coverage is now measured, attached to every evaluation item,
and reported as a distribution with quartile boundaries; P4 reports every score
by coverage quartile, which measures memorization instead of deleting the
evidence for it. A deleted item measures nothing.

  applied     near-duplicate input   Jaccard >= NEAR_THRESHOLD against any training text,
                                     P2's shingling / seed / permutations, imported not reimplemented
  measured    coverage ratio         fraction of the item's 13-grams present anywhere in training,
                                     attached per item, quartiles per eval set, NOT applied
  diagnostic  any-13-gram            P3's original criterion, reported, NOT applied
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
# The P3.1 coverage threshold. NOT a criterion any more: it is kept as a named
# constant for one purpose only -- reconciling the P3.2 record against the P3.1
# record, so the 2,483 restored items can be counted rather than asserted.
SUPERSEDED_P31_COVERAGE_MAX = 0.5
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
        criteria = ["near_duplicate"] if nn["jaccard"] >= NEAR_THRESHOLD else []
        out[key] = {
            "removed": bool(criteria), "criteria": criteria,
            "near_match": nn, "coverage_13": cov, "coverage_8_fraction": cov8["fraction"],
            "diag_any_13gram": cov["n_hit"] > 0, "diag_any_8gram": cov8["n_hit"] > 0,
            # Not applied. Recorded so build.py can count what P3.1 would have
            # removed and reconcile the restored items against that record.
            "diag_p31_coverage": cov["fraction"] > SUPERSEDED_P31_COVERAGE_MAX,
        }
    stats = {"train_unique_13grams": int(idx13.size), "train_unique_8grams": int(idx8.size),
             "train_texts_hashed_for_near_dup": near.size, "near_threshold": NEAR_THRESHOLD,
             "near_threshold_source": NEAR_THRESHOLD_SOURCE,
             "applied_criteria": ["near_duplicate"],
             "coverage_applied": False,
             "coverage_role": ("measured and attached to every evaluation item as train_ngram_coverage; "
                               "quartile boundaries per evaluation set are in the manifest; P4 reports "
                               "every score overall and by coverage quartile"),
             "superseded_p31_coverage_max": SUPERSEDED_P31_COVERAGE_MAX,
             "minhash_params": {"seed": p2near.SEED, "num_perm": p2near.NUM_PERM,
                                "shingle_size": p2near.SHINGLE_SIZE, "bands": near.bands, "rows": near.rows}}
    return out, stats


def quartiles(values) -> dict:
    """Quartile boundaries of an observed distribution -- nearest-rank, the same
    convention lengths.py uses. These are boundaries read off the data, not a
    threshold anyone chose."""
    v = sorted(values)
    if not v:
        return {"q25": 0.0, "q50": 0.0, "q75": 0.0, "min": 0.0, "max": 0.0, "n": 0}
    def at(q):
        return v[min(len(v) - 1, int(round(q * (len(v) - 1))))]
    return {"q25": at(.25), "q50": at(.50), "q75": at(.75), "min": v[0], "max": v[-1], "n": len(v)}


def quartile_of(value: float, b: dict) -> int:
    """1..4 by the recorded boundaries. Ties land in the lower quartile, so with
    a mass of identical values the bins are uneven -- the counts are reported so
    P4 sees that rather than assuming four equal bins."""
    if value <= b["q25"]:
        return 1
    if value <= b["q50"]:
        return 2
    if value <= b["q75"]:
        return 3
    return 4


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
    L = ["# P3.2 오염 검사 보고서\n",
         "> `manifests/datasets.manifest.json`의 **기록된 제거 사실**을 렌더링한다. 여기서 아무것도 다시 계산하지 않는다 "
         "(`docs/engineering-rules.md` 규칙 1). `make datasets-docs` 또는 `python -m datasets.contamination --render`.\n"]

    L.append("## 적용되는 기준은 하나다: 근접 중복\n")
    s = c["index"]
    L.append(f"**근접 중복 입력** — 학습 텍스트 중 어느 하나와 Jaccard ≥ **{s['near_threshold']}** "
             f"(출처: {s['near_threshold_source']}). P2의 `process/near.py`를 import한다 "
             f"(seed {s['minhash_params']['seed']}, 순열 {s['minhash_params']['num_perm']}, "
             f"{s['minhash_params']['shingle_size']}-gram 셰일, 밴드 {s['minhash_params']['bands']}×{s['minhash_params']['rows']}). 재구현하지 않았다.\n")
    L.append("시간 분할이 이미 같은 CVE가 학습과 평가에 동시에 있을 수 없음을 보장한다. 그러므로 남는 위험은 하나뿐이다 — "
             "**다른 CVE ID를 단 학습 입력의 근사 복사본**. 벤더는 권고문 사이에서 설명을 복사하고, 그 복사본은 시간 경계를 넘는다. "
             "이것이 실제 누수이고 제거한다.\n")
    r31 = c["reconciliation_with_p31"]
    L.append("## P3.1 대비 무엇이 바뀌었나 — 복원 정산\n")
    L.append("| 항목 | 건수 |\n|---|---|")
    L.append(f"| P3.1 기준(근접중복 ∪ 커버리지>0.5)이 제거했을 항목 | {r31['p31_removed_total']:,} |")
    L.append(f"| **P3.2가 실제로 제거한 항목 (근접 중복만)** | **{r31['p32_removed_total']:,}** |")
    L.append(f"| **복원된 항목 (커버리지만으로 제거됐던 것)** | **{r31['restored_coverage_only']:,}** |")
    L.append(f"\n항등식 `{r31['identity']}`. {r31['note']}\n")

    L.append("## 커버리지는 왜 더 이상 필터가 아닌가\n")
    L.append("커버리지 0.5는 **근거 없이 정해진 임계값**이었다 — 이 프로젝트가 P2의 빌려온 0.85를 비판한 바로 그 결함이다. "
             "그것이 잘라낸 항목들의 커버리지는 p25 0.581 / 중앙값 0.667로 **조밀한 띠 한가운데**였고, 그 띠의 정체는 "
             "Linux 커널 CVE와 템플릿을 쓰는 벤더다. 기록된 CNA 분포가 대가를 보여줬다: 평가 세트 두 개가 "
             "**필터링 전보다도** 학습 분포에서 더 멀어졌다. 편향이 줄어든 게 아니라 다른 편향으로 바뀐 것이다.\n")
    L.append("그래서 커버리지는 이제 **측정값**이다. 모든 평가 항목이 `train_ngram_coverage` 필드로 자기 커버리지를 들고 다니고, "
             "평가 세트마다 사분위 경계가 매니페스트에 기록된다. P4는 모든 점수를 **전체 및 커버리지 사분위별로** 보고한다. "
             "커버리지가 올라갈수록 정확도가 오르면 그 격차가 암기의 측정값이다. 오르지 않으면 그것도 똑같이 결과다. "
             "**삭제된 항목은 아무것도 측정하지 못한다.**\n")
    L.append(f"학습 측 인덱스: 고유 13-gram {s['train_unique_13grams']:,}, 8-gram {s['train_unique_8grams']:,}, "
             f"근접 중복용 해시 텍스트 {s['train_texts_hashed_for_near_dup']:,} (학습 4과제 입력+정답, 리플레이 프롬프트+응답). "
             f"커버리지 적용 여부: **{s['coverage_applied']}**.\n")

    L.append("## 평가 세트별 제거와 복원 (build.py가 수행하고 기록한 값)\n")
    L.append("| 평가 세트 | 검사 전 | **제거(근접중복)** | 제거율 | **복원(커버리지 전용)** | 최종 | *(진단)* P3.1이면 | *(진단)* 단일13-gram이면 |")
    L.append("|---|---|---|---|---|---|---|---|")
    for k, v in c["eval_sets"].items():
        L.append(f"| `{k}` | {v['before']:,} | **{v['removed']:,}** | {v['removed_fraction']:.1%} | "
                 f"**+{v['restored_p31_coverage_only']:,}** | {v['after']:,} | {v['diag_p31_criterion_would_remove']:,} | "
                 f"{v['diag_old_criterion_would_remove']:,} ({v['diag_old_criterion_fraction']:.1%}) |")
    L.append(f"\n총 제거 **{c['total_removed']:,}건**. 단일 13-gram 무관용(P3 원안)이었다면 **{c['total_diag_old_criterion']:,}건**이었다.\n")

    L.append("## 커버리지 분포 — 적용하지 않고 보고하는 값\n")
    L.append("평가 세트별 사분위 경계와 각 사분위에 속한 항목 수. 동일한 커버리지 값이 많으면 사분위가 고르게 나뉘지 않는다 — "
             "그 사실을 숨기지 않고 건수를 그대로 싣는다. P4는 이 경계를 그대로 써서 층화한다.\n")
    L.append("| 평가 세트 | min | q25 | q50 | q75 | max | q1 | q2 | q3 | q4 | 커버리지 0 |\n|---|---|---|---|---|---|---|---|---|---|---|")
    for k, v in c["eval_sets"].items():
        q, n_ = v["coverage_quartiles"], v["coverage_quartile_counts"]
        L.append(f"| `{k}` | {q['min']} | {q['q25']} | {q['q50']} | {q['q75']} | {q['max']} | "
                 f"{n_.get('q1',0):,} | {n_.get('q2',0):,} | {n_.get('q3',0):,} | {n_.get('q4',0):,} | "
                 f"{v['coverage_zero']:,} ({v['coverage_zero']/v['after']:.0%}) |")
    zero_heavy = [k for k, v in c["eval_sets"].items() if v["coverage_quartile_counts"].get("q2", 0) == 0]
    L.append(f"\n사분위가 고르지 않은 이유는 기록에 그대로 있다: 각 세트의 상당 부분이 **커버리지 정확히 0** — "
             f"학습과 13-gram을 하나도 공유하지 않는다. 그래서 q25와 q50 경계가 같은 값으로 붕괴하고 "
             f"{len(zero_heavy)}개 세트에서 q2 구간이 정의상 비어 있다. "
             "P4는 이 경계를 그대로 쓰되 **커버리지 0 그룹을 별도로** 보고해야 한다 — 그것이 실질적인 최저 구간이다.\n")
    L.append("\n**커버리지 비율(13-gram) 전체 분포** — 검사한 평가 항목 전부:\n")
    L.append("| 구간 | 항목 수 |\n|---|---|")
    for k, v in c["coverage_histogram"].items():
        L.append(f"| `{k}` | {v:,} |")
    L.append("\n**최근접 학습 항목과의 Jaccard 분포**:\n\n| 구간 | 항목 수 |\n|---|---|")
    for k, v in c["near_jaccard_histogram"].items():
        L.append(f"| `{k}` | {v:,} |")

    L.append("\n## CNA 분포 — 세 가지 버전 비교\n")
    L.append("TVD = 학습 세트 CNA 분포와의 총변동거리 (0 = 동일, 1 = 완전히 다름). 평가 세트가 학습 세트와 같은 CNA 구성을 가질수록 "
             "과제 난이도가 시간에 따라 달라지는 교란이 작다.\n")
    L.append("| 평가 세트 | 검사 전 | P3 단일13-gram 후 | P3.1 근접+커버리지 후 | **P3.2 근접만 후** | 상위 CNA (P3.2 후) |\n|---|---|---|---|---|---|")
    for k, v in c["cna_distribution"].items():
        top = ", ".join(f"{a} {n_}" for a, n_ in v["after_new_top"][:5])
        L.append(f"| `{k}` | {v['tvd_before']} | {v['tvd_after_old']} | {v['tvd_after_p31']} | **{v['tvd_after_new']}** | {top} |")
    d = c["cna_distribution"]
    b_p31 = [k for k, v in d.items() if v["tvd_after_new"] < v["tvd_after_p31"]]
    b_old = [k for k, v in d.items() if v["tvd_after_new"] < v["tvd_after_old"]]
    worse = [k for k, v in d.items() if v["tvd_after_new"] > v["tvd_before"] + 0.02]
    L.append(f"\n**판정**: {len(d)}개 CVE 평가 세트 중 **{len(b_p31)}개**에서 P3.2가 P3.1보다, **{len(b_old)}개**에서 P3보다 "
             "학습 분포에 가깝다"
             + (f"; 검사 전보다 눈에 띄게(TVD +0.02 초과) 멀어진 세트는 {worse}다." if worse else
                "; **검사 전보다 학습 분포에서 눈에 띄게(TVD +0.02 초과) 멀어진 세트는 하나도 없다** — "
                "커버리지 필터가 만들던 편향이 사라졌다.") + "\n")

    L.append("## 제거된 항목 — 전부 검사 가능\n")
    L.append(f"제거된 {c['total_removed']:,}건 각각의 ID·최근접 학습 항목·Jaccard·커버리지가 매니페스트 `removal_record`에 있다. 처음 몇 건:\n")
    L.append("| 예제 | 기준 | 최근접 학습 항목 | Jaccard | 커버리지 | 일치 13-gram 예 |\n|---|---|---|---|---|---|")
    for rec in manifest["removal_record"][:12]:
        L.append(f"| `{rec['example_id']}` | {','.join(rec['criteria'])} | `{rec['near_match']['key']}` | {rec['near_match']['jaccard']} | "
                 f"{rec['coverage_13']['fraction']} | `{(rec['coverage_13']['example_gram'] or '')[:60]}` |")
    L.append("\n## 교차 평가 검사\n")
    for k, v in c["cross_eval"].items():
        L.append(f"- `{k}`: {v} (0이어야 함)")
    rc = OUT / "contamination_recheck.json"
    if rc.exists():
        rj = json.loads(rc.read_text())
        L.append(f"\n## RE-CHECK (별도 파일, 제거 기록이 아님)\n\n`--assert-zero`가 최종 파일을 다시 검사한 결과: "
                 f"적용 기준(근접 중복) 초과 항목 **{rj['items_exceeding_criteria']}건** "
                 f"({'통과' if rj['items_exceeding_criteria']==0 else '실패'}). "
                 "이 숫자는 재검증이며 위의 제거 건수와 별개다.")
    out = REPORTS / "contamination.md"
    out.write_text("\n".join(L) + "\n", encoding="utf-8")
    return out


# --------------------------------------------------------------------- re-check
def recheck() -> int:
    """RE-CHECK: recompute the applied criterion on the final files. Writes to
    contamination_recheck.json, never to the removal record. Items with high
    13-gram coverage are expected to be present and are not flagged -- coverage
    is measured, not applied."""
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
    print(f"RE-CHECK: {len(evals):,} eval items re-screened; {len(bad)} exceed the applied criterion (near-duplicate)")
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
