"""The memorization probe: a direct measurement, not an inference from strata.

P3.2 removed 334 evaluation items as near-duplicates of training inputs
(Jaccard 0.750 to 1.000). They were excluded from every evaluation set and are
therefore uncontaminated as a probe: if a fine-tuned model does better on a
near-copy of something it trained on than on a matched item it did not, that
difference is memorization, measured directly.

  build   reconstruct the 334 items through the dataset's own example renderer
          (datasets.build.make_example), self-test that renderer against the
          23k evaluation items that still exist (prompt and target must be
          byte-identical for every one), then pick one matched control per probe
          item: same task, same split, SAME TRUE LABEL, nearest description
          length. Same label is a stricter form of "same label frequency" and
          needs no threshold; a probe item with no same-label item left in its
          evaluation set goes unmatched and is counted.
  score   probe accuracy minus control accuracy, per condition, with a paired
          bootstrap over (probe, control) pairs. Cond-0 is the floor: it never
          saw the training set, so any probe advantage there is item difficulty.
  render  reports/memorization.md (Korean).

Scoring uses the P4 scorers unchanged. Constrained decoding is the primary
reading because free-mode schema validity is near zero on cvss_vector in every
condition; both are reported.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from eval import strata  # noqa: E402
from eval.common import (  # noqa: E402
    EVAL_SPLITS, MANIFESTS, OUT, REPORTS, RUNS, SCHEMAS, SEED, HarnessError, iter_jsonl, write_json, write_jsonl,
)
from eval.scorers import schema as schema_scorer  # noqa: E402
from eval.stats import N_BOOT, _primary_flag, item_label  # noqa: E402

PROBE_DIR = RUNS / "probe"
TASKS = ("cve_to_cwe", "cvss_vector", "structured_extract")
MAX_VERSIONS = 16   # datasets/build.py; the reconstruction self-test catches any divergence


# ------------------------------------------------------------------ build
def _targets(row):
    """Targets exactly as datasets/build.py derives them. Verified, not trusted:
    build() checks this against every surviving evaluation item."""
    from datasets import cwe_policy
    out = {}
    res = cwe_policy.resolve(row)
    if res["bucket"] not in ("contested", "rejected") and res["cwe_id"] and row["description"]:
        out["cve_to_cwe"] = ({"cwe_id": res["cwe_id"]},
                             {"cwe_source": res["cwe_source"], "year": row["year"], "assigner": row["assigner"],
                              "dedup_stage": row["dedup_stage"], "guard_readmitted": False})
    cv = row.get("cvss31")
    if cv and row["description"]:
        t = {k: cv[k] for k in ("attackVector", "attackComplexity", "privilegesRequired", "userInteraction", "scope",
                                "confidentialityImpact", "integrityImpact", "availabilityImpact", "baseScore", "vectorString")}
        if not any(v is None for v in t.values()):
            out["cvss_vector"] = (t, {"year": row["year"], "assigner": row["assigner"], "dedup_stage": row["dedup_stage"],
                                      "baseSeverity": cv.get("baseSeverity")})
    aff = [a for a in row["affected"] if a["product"] and a["product"].strip().lower() != "n/a"]
    if len(aff) == 1:
        a = aff[0]
        vers = [v for v in a["versions"] if v.strip() and v.strip().lower() != "n/a"]
        vendor = (a["vendor"] or "").strip()
        if vendor and vendor.lower() != "n/a" and vers and len(vers) <= MAX_VERSIONS and row["description"]:
            out["structured_extract"] = ({"vendor": vendor, "product": a["product"].strip(), "versions": vers,
                                          "impact": (row["impacts"][0] if row["impacts"] else None)},
                                         {"year": row["year"], "assigner": row["assigner"], "dedup_stage": row["dedup_stage"],
                                          "impact_present": bool(row["impacts"]), "n_versions": len(vers)})
    return out


def build() -> dict:
    from datasets.build import make_example
    manifest = json.loads((MANIFESTS / "datasets.manifest.json").read_text())
    removed = manifest["removal_record"]
    need = {(r["task"], r["entity_id"]): r for r in removed}
    cve_rows = {}
    for row in iter_jsonl(OUT / "cve_table.jsonl"):
        cve_rows[row["cve_id"]] = row
    # --- self-test the reconstruction on the surviving evaluation items
    evals = {}
    for t in TASKS:
        for sp in EVAL_SPLITS:
            for e in iter_jsonl(OUT / t / f"{sp}.jsonl"):
                evals[(t, sp, e["entity_id"])] = e
    checked = mism = 0
    for (t, sp, cid), e in evals.items():
        tg = _targets(cve_rows[cid]).get(t)
        if tg is None:
            mism += 1; continue
        rec = make_example(t, cid, sp, cve_rows[cid]["description"], tg[0], tg[1])
        checked += 1
        if rec["prompt"] != e["prompt"] or rec["target_json"] != e["target_json"]:
            mism += 1
    if mism:
        raise HarnessError(f"reconstruction self-test failed: {mism} of {checked} surviving items differ")
    # --- reconstruct the probe items
    probe, missing = [], []
    for (t, cid), r in sorted(need.items()):
        row = cve_rows.get(cid)
        tg = _targets(row).get(t) if row else None
        if tg is None:
            missing.append(f"{t}:{cid}"); continue
        rec = make_example(t, cid, r["split"], row["description"], tg[0], tg[1])
        rec["kind"] = "probe"
        rec["near_match"] = r["near_match"]; rec["coverage_13"] = r["coverage_13"]["fraction"]
        rec["n_grams"] = strata.n_grams(rec["input"]); rec["label"] = item_label(t, rec["target"])
        probe.append(rec)
    # --- matched controls: same task, split, true label; nearest length; each used once
    pools = defaultdict(list)
    for (t, sp, cid), e in evals.items():
        pools[(t, sp, item_label(t, e["target"]))].append((strata.n_grams(e["input"]), e["example_id"]))
    used, controls, unmatched, dist = set(), {}, [], []
    for p in sorted(probe, key=lambda x: x["example_id"]):
        cands = [(abs(ng - p["n_grams"]), eid) for ng, eid in pools.get((p["task"], p["split"], p["label"]), [])
                 if eid not in used]
        if not cands:
            unmatched.append(p["example_id"]); continue
        d, eid = min(cands)
        used.add(eid); controls[p["example_id"]] = {"control_id": eid, "length_distance": d}; dist.append(d)
    PROBE_DIR.mkdir(parents=True, exist_ok=True)
    n, sha = write_jsonl(PROBE_DIR / "probe_items.jsonl", sorted(probe, key=lambda x: x["example_id"]))
    jac = sorted(p["near_match"]["jaccard"] for p in probe)
    summary = {
        "n_removed_in_record": len(removed), "n_probe_items": n, "probe_items_sha256": sha,
        "reconstruction_self_test": {"surviving_items_checked": checked, "mismatches": mism},
        "not_reconstructible": missing,
        "by_task_split": dict(Counter(f"{p['task']}/{p['split']}" for p in probe)),
        "probe_jaccard": {"min": jac[0], "median": jac[len(jac) // 2], "max": jac[-1]},
        "matched": len(controls), "unmatched": len(unmatched), "unmatched_ids": unmatched,
        "matching": "same task, same split, same true label (cwe_id / vectorString / vendor), nearest n_grams; "
                    "greedy in example_id order, each control used once",
        "length_distance": {"median": (sorted(dist)[len(dist) // 2] if dist else None),
                            "p90": (sorted(dist)[int(0.9 * (len(dist) - 1))] if dist else None),
                            "max": (max(dist) if dist else None)},
        "controls": controls,
    }
    write_json(PROBE_DIR / "controls.json", summary)
    return summary


# ------------------------------------------------------------------ score
def _outputs_by_key(path):
    return {(r["task"], r["decoding"], r["example_id"]): r for r in iter_jsonl(path)}


def paired_boot(pairs, seed=SEED):
    """pairs: [(probe_correct, control_correct)]. Resample pairs."""
    a = np.asarray(pairs, dtype=float)
    if not len(a):
        return {"n_pairs": 0}
    rng = np.random.default_rng(seed)
    idx = rng.integers(0, len(a), size=(N_BOOT, len(a)))
    d = (a[idx, 0] - a[idx, 1]).mean(axis=1)
    return {"n_pairs": int(len(a)), "probe_acc": float(a[:, 0].mean()), "control_acc": float(a[:, 1].mean()),
            "diff": float(a[:, 0].mean() - a[:, 1].mean()),
            "diff_ci95": [float(np.percentile(d, 2.5)), float(np.percentile(d, 97.5))],
            "probe_only_correct": int(((a[:, 0] == 1) & (a[:, 1] == 0)).sum()),
            "control_only_correct": int(((a[:, 0] == 0) & (a[:, 1] == 1)).sum())}


def score(runs) -> dict:
    ctl = json.loads((PROBE_DIR / "controls.json").read_text())["controls"]
    probe = {p["example_id"]: p for p in iter_jsonl(PROBE_DIR / "probe_items.jsonl")}
    evals = {}
    for t in TASKS:
        for sp in EVAL_SPLITS:
            for e in iter_jsonl(OUT / t / f"{sp}.jsonl"):
                evals[e["example_id"]] = e
    validators = schema_scorer.load_validators(SCHEMAS, TASKS)

    def correct(task, text, target):
        s = schema_scorer.score_one(text, validators[task][1])
        return bool(s["schema_valid"] and _primary_flag(task, s["value"], target)), bool(s["schema_valid"])

    out = {"runs": {}, "controls_file": "runs/probe/controls.json", "primary_decoding": "constrained",
           "why_primary": "free-mode schema validity on cvss_vector is near zero in every condition, so free-mode "
                          "accuracy there measures formatting, not knowledge; both decodings are reported"}
    for run in runs:
        po = _outputs_by_key(RUNS / f"{run}_probe" / "outputs.jsonl")
        eo = _outputs_by_key(RUNS / run / "outputs.jsonl")
        rec = {}
        for mode in ("constrained", "free"):
            per_task, pooled = {}, []
            sv_probe, sv_ctl = [], []
            for pid, c in ctl.items():
                p = probe[pid]; t = p["task"]
                pr = po.get((t, mode, pid)); cr = eo.get((t, mode, c["control_id"]))
                if pr is None or cr is None:
                    continue
                pc, ps = correct(t, pr["output_text"], p["target"])
                cc, cs = correct(t, cr["output_text"], evals[c["control_id"]]["target"])
                per_task.setdefault(t, []).append((pc, cc)); pooled.append((pc, cc))
                sv_probe.append(ps); sv_ctl.append(cs)
            rec[mode] = {"pooled": paired_boot(pooled),
                         "by_task": {t: paired_boot(v) for t, v in sorted(per_task.items())},
                         "schema_valid": {"probe": float(np.mean(sv_probe)) if sv_probe else None,
                                          "control": float(np.mean(sv_ctl)) if sv_ctl else None}}
        out["runs"][run] = rec
    # memorization = probe advantage above the Cond-0 floor
    base = out["runs"].get(runs[0], {})
    for run in runs[1:]:
        for mode in ("constrained", "free"):
            b, r = base[mode]["pooled"], out["runs"][run][mode]["pooled"]
            out["runs"][run][mode]["above_cond0_floor"] = {
                "diff_minus_baseline_diff": r["diff"] - b["diff"],
                "note": "positive means this condition's probe advantage exceeds the base model's, which is the memorization signal"}
    write_json(PROBE_DIR / "scores.json", out)
    return out


# ------------------------------------------------------------------ render
def pc(x):
    return "—" if x is None else f"{100*x:.1f}%"


def render(runs) -> Path:
    s = json.loads((PROBE_DIR / "scores.json").read_text())
    b = json.loads((PROBE_DIR / "controls.json").read_text())
    L = ["# P5 암기 탐침 — 직접 측정\n",
         "> `runs/probe/scores.json`과 `controls.json`의 기록을 렌더링한다. 재생성: `python -m eval.probe --render`.\n",
         "## 탐침이란\n",
         f"P3.2가 근접 중복으로 제거한 평가 항목 **{b['n_probe_items']}건** — 학습 입력의 근사 복사본 (Jaccard 최소 {b['probe_jaccard']['min']}, "
         f"중앙값 {b['probe_jaccard']['median']}, **최대 {b['probe_jaccard']['max']}**). 평가 세트에서 빠져 있었으므로 탐침으로서 오염되지 않았다. "
         "미세조정된 모델이 학습에서 본 것의 근사 복사본을 **같은 라벨·비슷한 길이의 짝지은 대조 항목**보다 더 잘 맞히면, 그 차이가 암기의 직접 측정값이다.\n",
         f"- 재구성 자체검증: 살아남은 평가 항목 {b['reconstruction_self_test']['surviving_items_checked']:,}건을 같은 렌더러로 다시 만들어 "
         f"프롬프트·정답 바이트 일치 — 불일치 **{b['reconstruction_self_test']['mismatches']}건**.",
         f"- 대조 짝짓기: {b['matching']}. 짝지어진 {b['matched']}건, **짝 없음 {b['unmatched']}건** (같은 세트에 같은 라벨의 항목이 남아 있지 않음). "
         f"길이 거리 중앙값 {b['length_distance']['median']}, p90 {b['length_distance']['p90']}, 최대 {b['length_distance']['max']} (13-gram 수 기준).",
         f"- 과제·분할별 탐침 수: {b['by_task_split']}\n",
         "## 결과 — 탐침 정확도 − 대조 정확도 (짝 부트스트랩 95% 구간)\n",
         f"주 판독은 **{s['primary_decoding']}**: {s['why_primary']}\n"]
    for mode in ("constrained", "free"):
        L.append(f"### {mode}\n")
        L.append("| 조건 | 짝 수 | 탐침 정확도 | 대조 정확도 | **차이** | 95% 구간 | 탐침만 정답 / 대조만 정답 | Cond-0 바닥 대비 |\n|---|---|---|---|---|---|---|---|")
        for run in runs:
            r = s["runs"][run][mode]; p = r["pooled"]
            above = r.get("above_cond0_floor", {}).get("diff_minus_baseline_diff")
            L.append(f"| `{run}` | {p['n_pairs']} | {pc(p['probe_acc'])} | {pc(p['control_acc'])} | **{100*p['diff']:+.1f}pp** | "
                     f"[{100*p['diff_ci95'][0]:+.1f}, {100*p['diff_ci95'][1]:+.1f}] | {p['probe_only_correct']} / {p['control_only_correct']} | "
                     f"{('%+.1fpp' % (100*above)) if above is not None else '(바닥)'} |")
        L.append("\n과제별:\n\n| 조건 | 과제 | 짝 수 | 탐침 | 대조 | 차이 | 95% 구간 |\n|---|---|---|---|---|---|---|")
        for run in runs:
            for t, p in s["runs"][run][mode]["by_task"].items():
                L.append(f"| `{run}` | `{t}` | {p['n_pairs']} | {pc(p['probe_acc'])} | {pc(p['control_acc'])} | "
                         f"{100*p['diff']:+.1f}pp | [{100*p['diff_ci95'][0]:+.1f}, {100*p['diff_ci95'][1]:+.1f}] |")
        L.append("")
    L.append("## 읽는 법\n")
    L.append("- **Cond-0 행이 바닥이다.** 기준선은 학습 세트를 본 적이 없으므로 거기서 탐침이 앞선다면 그것은 항목 난이도(근사 복사본이 "
             "많은 항목은 정형화된 항목이다)이지 암기가 아니다.")
    L.append("- 암기 신호는 **조건의 차이에서 Cond-0의 차이를 뺀 값**이다. 그 값의 구간이 0을 포함하면 이 탐침 크기에서 암기는 검출되지 않은 것이다 — "
             "'약간 있다'가 아니라 '검출되지 않음'이다.")
    L.append("- 이 측정이 계층 기반 추론을 **대체**한다. 계층 표는 결과 보고서에 남지만 더 이상 암기 주장의 근거가 아니다.")
    L.append(f"- 탐침은 {b['n_probe_items']}건이고 짝지은 것은 {b['matched']}건이다. 검출 가능한 최소 차이는 결과 보고서의 MDD 표를 참조하라; "
             "이 크기에서 수 퍼센트포인트 이하의 차이는 보이지 않는다.\n")
    out = REPORTS / "memorization.md"
    out.write_text("\n".join(L) + "\n", encoding="utf-8")
    return out


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--build", action="store_true")
    ap.add_argument("--runs", default="", help="comma separated, baseline first")
    ap.add_argument("--render", action="store_true")
    a = ap.parse_args()
    if a.build:
        r = build(); print(json.dumps({k: v for k, v in r.items() if k != "controls"}, indent=1, ensure_ascii=False))
    if a.runs:
        runs = a.runs.split(",")
        r = score(runs)
        for run in runs:
            p = r["runs"][run]["constrained"]["pooled"]
            print(f"{run}: constrained probe {p['probe_acc']:.3f} control {p['control_acc']:.3f} diff {p['diff']:+.3f} {p['diff_ci95']}")
        if a.render:
            print(render(runs))
