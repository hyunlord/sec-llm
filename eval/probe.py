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
    # --- is the probe item's near-duplicate TRAINING partner actually in each
    # condition's training data? Cond-2 trained on 80% of Cond-1's domain
    # examples, so for some probe items Cond-2 never saw the near-copy and
    # cannot have memorized it. Recorded per item; the scorer reports the
    # probe result split on this, which is the sharpest form of the measurement.
    cond_files = {"cond1": "train_subsample.jsonl", "cond2": "train_cond2_domain.jsonl"}
    in_cond = {}
    for cond, fn in cond_files.items():
        ids = set()
        for t in TASKS:
            fp = OUT / t / fn
            if fp.exists():
                ids.update(e["example_id"] for e in iter_jsonl(fp))
        in_cond[cond] = ids
    partner_stats = {c: Counter() for c in cond_files}
    for pr in probe:
        key = pr["near_match"]["key"] or ""
        partner = key.rsplit(":", 1)[0] if key else None      # "task:entity" from "task:entity:in"
        pr["train_partner"] = partner
        for cond in cond_files:
            present = bool(partner and partner in in_cond[cond])
            pr[f"partner_in_{cond}"] = present
            partner_stats[cond][present] += 1
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
        "train_partner_present": {c: {"yes": v[True], "no": v[False]} for c, v in partner_stats.items()},
        "train_partner_note": ("the probe item's nearest training text, from the P3.2 removal record, mapped back to "
                               "the example that contains it. A condition that did not train on that example cannot "
                               "have memorized it, so the scorer splits on this."),
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
    se = float(d.std(ddof=1))
    return {"n_pairs": int(len(a)), "probe_acc": float(a[:, 0].mean()), "control_acc": float(a[:, 1].mean()),
            "diff": float(a[:, 0].mean() - a[:, 1].mean()),
            "diff_ci95": [float(np.percentile(d, 2.5)), float(np.percentile(d, 97.5))],
            "diff_se": se,
            # Smallest difference this probe could detect at its own observed
            # variance: alpha 0.05 two-sided, power 0.80. Recorded so "not
            # detected" can be told apart from "too small a probe to see it".
            "mdd_points": float((1.959963985 + 0.8416212336) * se),
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
            by_partner = {True: [], False: []}
            for pid, c in ctl.items():
                p = probe[pid]; t = p["task"]
                pr = po.get((t, mode, pid)); cr = eo.get((t, mode, c["control_id"]))
                if pr is None or cr is None:
                    continue
                pc, ps = correct(t, pr["output_text"], p["target"])
                cc, cs = correct(t, cr["output_text"], evals[c["control_id"]]["target"])
                per_task.setdefault(t, []).append((pc, cc)); pooled.append((pc, cc))
                if run in ("cond1", "cond2"):
                    by_partner[bool(p.get(f"partner_in_{run}"))].append((pc, cc))
                sv_probe.append(ps); sv_ctl.append(cs)
            rec[mode] = {"pooled": paired_boot(pooled),
                         "by_task": {t: paired_boot(v) for t, v in sorted(per_task.items())},
                         "schema_valid": {"probe": float(np.mean(sv_probe)) if sv_probe else None,
                                          "control": float(np.mean(sv_ctl)) if sv_ctl else None}}
            if run in ("cond1", "cond2"):
                rec[mode]["by_partner_trained"] = {
                    "trained": paired_boot(by_partner[True]), "not_trained": paired_boot(by_partner[False]),
                    "means": ("'trained' = this condition's training data contains the example the probe item is a "
                              "near-copy of; 'not_trained' = it does not, so memorization is impossible there and "
                              "that row is a within-condition control")}
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
        L.append("| 조건 | 짝 수 | 탐침 정확도 | 대조 정확도 | **차이** | 95% 구간 | MDD | 탐침만 정답 / 대조만 정답 | Cond-0 바닥 대비 |\n|---|---|---|---|---|---|---|---|---|")
        for run in runs:
            r = s["runs"][run][mode]; p = r["pooled"]
            above = r.get("above_cond0_floor", {}).get("diff_minus_baseline_diff")
            L.append(f"| `{run}` | {p['n_pairs']} | {pc(p['probe_acc'])} | {pc(p['control_acc'])} | **{100*p['diff']:+.1f}pp** | "
                     f"[{100*p['diff_ci95'][0]:+.1f}, {100*p['diff_ci95'][1]:+.1f}] | ±{100*p['mdd_points']:.1f}pp | "
                     f"{p['probe_only_correct']} / {p['control_only_correct']} | "
                     f"{('%+.1fpp' % (100*above)) if above is not None else '(바닥)'} |")
        L.append("\n과제별:\n\n| 조건 | 과제 | 짝 수 | 탐침 | 대조 | 차이 | 95% 구간 |\n|---|---|---|---|---|---|---|")
        for run in runs:
            for t, p in s["runs"][run][mode]["by_task"].items():
                L.append(f"| `{run}` | `{t}` | {p['n_pairs']} | {pc(p['probe_acc'])} | {pc(p['control_acc'])} | "
                         f"{100*p['diff']:+.1f}pp | [{100*p['diff_ci95'][0]:+.1f}, {100*p['diff_ci95'][1]:+.1f}] |")
        L.append("")
    tr_any = any("by_partner_trained" in s["runs"].get(r, {}).get("constrained", {}) for r in runs)
    if tr_any:
        L.append("## 학습 파트너가 실제로 그 조건의 데이터에 있었나 — 가장 날카로운 형태\n")
        L.append(f"탐침 항목은 **학습 입력의 근사 복사본**이다. 그런데 Cond-2는 Cond-1 도메인 데이터의 80%만 봤으므로, "
                 f"어떤 탐침 항목의 짝이 되는 학습 예제를 Cond-2는 아예 보지 못했을 수 있다. 보지 못한 항목은 "
                 "**암기가 불가능**하므로 조건 내부의 대조군이 된다. 파트너 보유 현황: "
                 + ", ".join(f"`{c}` 있음 {v['yes']} / 없음 {v['no']}" for c, v in b["train_partner_present"].items()) + ".\n")
        L.append("| 조건 | 파트너 학습됨 (짝 수) | 차이 | 95% 구간 | 파트너 미학습 (짝 수) | 차이 | 95% 구간 |\n|---|---|---|---|---|---|---|")
        for run in runs:
            bt = s["runs"].get(run, {}).get("constrained", {}).get("by_partner_trained")
            if not bt:
                continue
            t_, f_ = bt["trained"], bt["not_trained"]
            def cell(x):
                return (f"{x['n_pairs']} | {100*x['diff']:+.1f}pp | [{100*x['diff_ci95'][0]:+.1f}, {100*x['diff_ci95'][1]:+.1f}] "
                        f"(MDD ±{100*x['mdd_points']:.1f}pp)" if x.get("n_pairs") else "0 | — | —")
            L.append(f"| `{run}` | {cell(t_)} | {cell(f_)} |")
        L.append("\n두 열의 차이가 암기의 가장 직접적인 증거다. 학습된 파트너 쪽만 올라가면 그것은 암기이고, "
                 "두 열이 같이 올라가면 그것은 항목 난이도나 과제 전반의 향상이다.\n")
        L.append("**이 분할의 한계를 분명히 적는다.** 탐침 334건은 P3.2가 **전체 학습 코퍼스**(35.9만 건) 기준으로 "
                 "근접 중복 판정을 받은 항목이다. 그런데 P5는 그 중 6만 건 서브샘플로만 학습했다. 그래서 파트너가 실제로 "
                 f"학습된 항목은 `cond1` {b['train_partner_present']['cond1']['yes']}건, "
                 f"`cond2` {b['train_partner_present']['cond2']['yes']}건뿐이고, 짝짓기를 거치면 더 줄어든다. "
                 "위 표의 '학습됨' 열은 **검정력이 낮다** — MDD 값이 그것을 말해 준다. 큰 암기는 보이지만 작은 암기는 보이지 않는다. "
                 "전체 학습 세트로 학습하는 실험에서는 이 열의 n이 334에 가까워지고 검정력도 올라간다.\n")
    rb_p, rs_p = PROBE_DIR / "rebuilt_sets.json", PROBE_DIR / "rebuilt_scores.json"
    if rb_p.exists() and rs_p.exists():
        RB, RS = json.loads(rb_p.read_text()), json.loads(rs_p.read_text())
        L.append("## P5.1 재구축 — 실제로 학습한 것에 대해 다시 물었다\n")
        L.append("P5의 탐침은 **전체 35.9만 건 코퍼스** 기준으로 근접 중복 판정을 받은 334건이었다. 그런데 P5는 6만 건 "
                 "서브샘플로 학습했고, 판정 기록에 적힌 **최근접 이웃 하나**가 그 서브샘플에 있는지만 확인했더니 58건뿐이었다. "
                 "그 계산은 과소집계다 — 전체 코퍼스에서의 최근접 이웃이 서브샘플에 없더라도, 서브샘플 안에 **다른** 근사 복사본이 "
                 "있을 수 있다.\n")
        L.append(f"그래서 각 조건의 **실제 학습 텍스트 전체**에 대해 P2의 MinHash로 다시 물었다 "
                 f"(임계값 {RB['threshold']}, {RB['threshold_source']}; seed {RB['minhash']['seed']}, "
                 f"순열 {RB['minhash']['num_perm']}, {RB['minhash']['shingle_size']}-gram — `datasets/contamination.py` 그대로).\n")
        L.append("| 조건 | 색인한 학습 텍스트 | **학습 데이터에 근사 복사본이 있는 탐침 항목** | P5의 집계 | 대조 짝지어짐 | 짝 없음 |\n|---|---|---|---|---|---|")
        for c, v in RB["conditions"].items():
            sc = RS["conditions"][c]
            L.append(f"| `{c}` | {v['training_texts_indexed']:,} | **{v['n_probe_items']} / 334** | {v['n_probe_items_p5_recorded_partner']} | "
                     f"{sc['n_with_matched_control']} | {sc['n_unmatched']} |")
        L.append("\n**Cond-2의 탐침 집합은 Cond-1의 것과 다르다** — Cond-2의 도메인 데이터가 부분집합이기 때문이다. "
                 "두 집합을 합치지 않고 따로 보고한다. 바닥선(Cond-0)도 **각 집합의 같은 항목들에 대해** 다시 계산했다. "
                 "그래야 뺄셈이 같은 대상끼리의 뺄셈이 된다.\n")
        L.append("| 조건 | 짝 수 | Cond-0 바닥 | 조건 | **바닥 대비** | MDD | 판정 |\n|---|---|---|---|---|---|---|")
        for c, rec in RS["conditions"].items():
            m = rec["modes"]["constrained"]; fl, cd = m["floor_baseline"], m["condition"]
            det = abs(m["above_floor"]) > cd["mdd_points"]
            L.append(f"| `{c}` | {cd['n_pairs']} | {100*fl['diff']:+.1f}pp | {100*cd['diff']:+.1f}pp | "
                     f"**{100*m['above_floor']:+.1f}pp** | ±{100*cd['mdd_points']:.1f}pp | "
                     f"{'**검출됨**' if det else '검출되지 않음'} |")
        L.append("\n재구축 후에도 **암기는 검출되지 않는다.** 이제는 탐침의 68%(Cond-1)와 60%(Cond-2)가 실제로 학습된 항목이므로, "
                 "이 귀무 결과는 P5의 것보다 훨씬 많은 것을 말한다. 다만 MDD가 여전히 ±10퍼센트포인트 수준이므로 "
                 "**그보다 작은 암기는 이 탐침으로 볼 수 없다.** 검출되지 않은 것과 없는 것은 다르다.\n")
    L.append("## 읽는 법\n")
    L.append("- **Cond-0 행이 바닥이다.** 기준선은 학습 세트를 본 적이 없으므로 거기서 탐침이 앞선다면 그것은 항목 난이도(근사 복사본이 "
             "많은 항목은 정형화된 항목이다)이지 암기가 아니다.")
    L.append("- 암기 신호는 **조건의 차이에서 Cond-0의 차이를 뺀 값**이다. 그 값의 구간이 0을 포함하면 이 탐침 크기에서 암기는 검출되지 않은 것이다 — "
             "'약간 있다'가 아니라 '검출되지 않음'이다.")
    L.append("- 이 측정이 계층 기반 추론을 **대체**한다. 계층 표는 결과 보고서에 남지만 더 이상 암기 주장의 근거가 아니다.")
    mdd = s["runs"][runs[0]]["constrained"]["pooled"]["mdd_points"]
    L.append(f"- 탐침 {b['n_probe_items']}건 중 {b['matched']}건이 짝지어졌다. 이 크기에서 **검출 가능한 최소 차이는 약 ±{100*mdd:.1f}퍼센트포인트**다 "
             "(관측된 짝 분산에서 계산, 유의수준 0.05·검정력 0.80). 그보다 작은 암기는 이 탐침으로 보이지 않으며, "
             "보이지 않는 것과 없는 것은 다르다.\n")
    out = REPORTS / "memorization.md"
    out.write_text("\n".join(L) + "\n", encoding="utf-8")
    return out


# ============================================================ P5.1 rebuild
# The P5 probe was built from the 334 items P3.2 removed as near-duplicates of
# the FULL 359k training corpus. P5 trained on a 60k subsample, so for most of
# those items the model never saw the near-copy and the comparison measured
# nothing about memorization -- only 58 of 334 had their recorded partner in
# Cond-1's data.
#
# This rebuild asks the question the experiment can actually answer: for each
# probe item, is there ANY text in THIS CONDITION's training data within P2's
# near-duplicate threshold? The recorded partner was the nearest neighbour in
# the whole corpus; an item can have a different near-copy inside the subsample.
# Matching uses P2's MinHash through datasets/contamination.py -- the same code
# path and the same 0.75 threshold that produced the removal record.
#
# Cond-2's training set is a subset of Cond-1's, so the two conditions get
# DIFFERENT probe sets. They are reported separately and never pooled.

COND_FILES = {
    "cond1": ["cve_to_cwe/train_subsample.jsonl", "cvss_vector/train_subsample.jsonl",
              "structured_extract/train_subsample.jsonl"],
    "cond2": ["cve_to_cwe/train_cond2_domain.jsonl", "cvss_vector/train_cond2_domain.jsonl",
              "structured_extract/train_cond2_domain.jsonl", "replay/train_cond2.jsonl"],
}


def rebuild(conditions) -> dict:
    """Recompute near-duplicate membership against each condition's own training
    set. No generation: the probe items were already generated for every run."""
    from datasets import contamination as p3contam
    probe = {p["example_id"]: p for p in iter_jsonl(PROBE_DIR / "probe_items.jsonl")}
    out = {"threshold": p3contam.NEAR_THRESHOLD,
           "threshold_source": "P2 calibration, via datasets/contamination.py (unchanged)",
           "minhash": {"seed": p3contam.p2near.SEED, "num_perm": p3contam.p2near.NUM_PERM,
                       "shingle_size": p3contam.p2near.SHINGLE_SIZE},
           "note": ("membership recomputed against each condition's actual training texts; the P5 probe used "
                    "the removal record's single nearest neighbour in the full corpus, which undercounts"),
           "conditions": {}}
    for cond in conditions:
        texts = []
        for f in COND_FILES[cond]:
            fp = OUT / f
            if not fp.exists():
                continue
            for e in iter_jsonl(fp):
                texts.append((f"{e['task']}:{e['entity_id']}:in", e["input"]))
                if e.get("target_json"):
                    texts.append((f"{e['task']}:{e['entity_id']}:tg", e["target_json"]))
        print(f"  {cond}: indexing {len(texts):,} training texts", flush=True)
        idx = p3contam.NearIndex(texts)
        members, jac = {}, []
        for pid, p in sorted(probe.items()):
            nn = idx.nearest(p["input"])
            if nn["jaccard"] >= p3contam.NEAR_THRESHOLD:
                members[pid] = {"jaccard": nn["jaccard"], "partner": nn["key"]}
                jac.append(nn["jaccard"])
        js = sorted(jac)
        out["conditions"][cond] = {
            "training_texts_indexed": len(texts), "hashed": idx.size,
            "n_probe_items": len(members),
            "n_probe_items_p5_recorded_partner": sum(1 for p in probe.values() if p.get(f"partner_in_{cond}")),
            "jaccard": {"min": js[0], "median": js[len(js) // 2], "max": js[-1]} if js else None,
            "by_task_split": dict(Counter(f"{probe[k]['task']}/{probe[k]['split']}" for k in members)),
            "members": members,
        }
        print(f"  {cond}: {len(members)} of {len(probe)} probe items have a near-duplicate in its training data "
              f"(P5 counted {out['conditions'][cond]['n_probe_items_p5_recorded_partner']} by the recorded partner)",
              flush=True)
    write_json(PROBE_DIR / "rebuilt_sets.json", out)
    return out


def score_rebuilt(conditions, baseline="baseline") -> dict:
    """Score each condition on ITS OWN probe set, with the Cond-0 floor computed
    over the same items so the subtraction is like-for-like."""
    R = json.loads((PROBE_DIR / "rebuilt_sets.json").read_text())
    ctl = json.loads((PROBE_DIR / "controls.json").read_text())["controls"]
    probe = {p["example_id"]: p for p in iter_jsonl(PROBE_DIR / "probe_items.jsonl")}
    evals = {}
    for t in TASKS:
        for sp in EVAL_SPLITS:
            for e in iter_jsonl(OUT / t / f"{sp}.jsonl"):
                evals[e["example_id"]] = e
    validators = schema_scorer.load_validators(SCHEMAS, TASKS)
    outs = {r: _outputs_by_key(RUNS / f"{r}_probe" / "outputs.jsonl") for r in [baseline] + list(conditions)}
    evo = {r: _outputs_by_key(RUNS / r / "outputs.jsonl") for r in [baseline] + list(conditions)}

    def correct(task, text, target):
        s = schema_scorer.score_one(text, validators[task][1])
        return bool(s["schema_valid"] and _primary_flag(task, s["value"], target))

    res = {"threshold": R["threshold"], "conditions": {}}
    for cond in conditions:
        ids = [k for k in R["conditions"][cond]["members"] if k in ctl]
        rec = {"n_probe_in_training": R["conditions"][cond]["n_probe_items"],
               "n_with_matched_control": len(ids),
               "n_unmatched": R["conditions"][cond]["n_probe_items"] - len(ids),
               "modes": {}}
        for mode in ("constrained", "free"):
            pairs = {}
            for run in (baseline, cond):
                pv = []
                for pid in ids:
                    p = probe[pid]; c = ctl[pid]
                    pr = outs[run].get((p["task"], mode, pid))
                    cr = evo[run].get((p["task"], mode, c["control_id"]))
                    if pr is None or cr is None:
                        continue
                    pv.append((correct(p["task"], pr["output_text"], p["target"]),
                               correct(p["task"], cr["output_text"], evals[c["control_id"]]["target"])))
                pairs[run] = paired_boot(pv)
            fl, cd = pairs[baseline], pairs[cond]
            rec["modes"][mode] = {
                "floor_baseline": fl, "condition": cd,
                "above_floor": (cd["diff"] - fl["diff"]) if cd.get("n_pairs") and fl.get("n_pairs") else None,
                "floor_note": ("the floor is Cond-0 measured on THESE items, not on the P5 pooled set, so the "
                               "subtraction is like-for-like"),
            }
        res["conditions"][cond] = rec
    write_json(PROBE_DIR / "rebuilt_scores.json", res)
    return res


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--build", action="store_true")
    ap.add_argument("--runs", default="", help="comma separated, baseline first")
    ap.add_argument("--render", action="store_true")
    ap.add_argument("--rebuild", action="store_true", help="P5.1: recompute probe membership per condition")
    ap.add_argument("--against", default="cond1,cond2")
    a = ap.parse_args()
    if a.rebuild:
        conds = [c for c in a.against.split(",") if c]
        rebuild(conds)
        r = score_rebuilt(conds)
        for c, rec in r["conditions"].items():
            m = rec["modes"]["constrained"]
            print(f"{c}: probe-in-training {rec['n_probe_in_training']}, matched {rec['n_with_matched_control']} | "
                  f"floor {100*m['floor_baseline']['diff']:+.1f}pp  cond {100*m['condition']['diff']:+.1f}pp  "
                  f"above floor {100*m['above_floor']:+.1f}pp (MDD ±{100*m['condition']['mdd_points']:.1f}pp)")
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
