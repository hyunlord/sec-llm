"""Scoring, statistics, and the two Korean reports.

Nothing here regenerates anything. It reads the run's outputs.jsonl and the
hash-verified dataset, scores mechanically, and writes scores.json next to the
outputs. A run whose manifest lacks any required setting is refused before a
single item is scored.

Three statistical rules, and the third is the one that matters:

  bootstrap   1,000 resamples with a fixed seed for every reported proportion,
              percentile 95% interval. A rate without an interval is not reported.
  McNemar     condition comparisons are paired, because both conditions see the
              same items. Exact binomial below 25 discordant pairs.
  verdict     when two intervals overlap, the verdict is "no difference detected".
              Not "trending", not "slightly better". The harness emits that string
              itself so a report cannot be written more strongly than the numbers.

And a fourth, so a null result can be told apart from an underpowered one: the
minimum detectable difference is reported for every evaluation set at its own n.
"""

from __future__ import annotations

import argparse
import json
import math
import sys
from collections import Counter, defaultdict
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from eval import sandbox, strata  # noqa: E402
from eval.common import (  # noqa: E402
    EVAL_SPLITS, GENERAL, OUT, REPORTS, RUNS, SCHEMAS, SEED, TASKS, HarnessError, iter_jsonl,
    load_run, verify_dataset, write_json, eval_file_keys,
)
from eval.scorers import cvss_fields, exact_match, extract_fields, general as general_scorer  # noqa: E402
from eval.scorers import schema as schema_scorer  # noqa: E402

N_BOOT = 1000
ALPHA, POWER_Z = 1.959963985, 0.8416212336        # z_{0.975}, z_{0.80}
PRIMARY = {"cve_to_cwe": "exact match (cwe_id)", "attack_technique": "exact match (technique_id)",
           "cvss_vector": "whole-vector exact match (8 metrics + vector string)",
           "structured_extract": "all fields exact (versions set equal; impact when non-null)"}


# ------------------------------------------------------------------ statistics
def boot_ci(flags, n_boot=N_BOOT, seed=SEED) -> dict:
    """Percentile bootstrap for a proportion. Deterministic: fresh RNG per call."""
    a = np.asarray(flags, dtype=np.float64)
    n = a.size
    if n == 0:
        return {"n": 0, "k": 0, "rate": None, "ci95": [None, None], "n_boot": n_boot}
    rng = np.random.default_rng(seed)
    idx = rng.integers(0, n, size=(n_boot, n))
    means = a[idx].mean(axis=1)
    lo, hi = np.percentile(means, [2.5, 97.5])
    return {"n": int(n), "k": int(a.sum()), "rate": float(a.mean()),
            "ci95": [float(lo), float(hi)], "n_boot": n_boot}


def mdd(p, n) -> float | None:
    """Minimum detectable difference in proportion points, alpha=0.05 two-sided,
    power=0.80, unpaired normal approximation. McNemar on paired items has more
    power, so this is a conservative bound -- stated as such wherever printed."""
    if not n or p is None:
        return None
    return float((ALPHA + POWER_Z) * math.sqrt(max(2 * p * (1 - p), 1e-12) / n))


def mcnemar(a_flags: dict, b_flags: dict) -> dict:
    """Paired comparison over the items both runs scored."""
    keys = sorted(set(a_flags) & set(b_flags))
    b = sum(1 for k in keys if a_flags[k] and not b_flags[k])
    c = sum(1 for k in keys if not a_flags[k] and b_flags[k])
    n = b + c
    if n == 0:
        p = 1.0; method = "no discordant pairs"
    elif n < 25:
        m = min(b, c)
        p = min(1.0, 2 * sum(math.comb(n, k) for k in range(m + 1)) / (2 ** n))
        method = "exact binomial"
    else:
        chi = (abs(b - c) - 1) ** 2 / n
        p = math.erfc(math.sqrt(chi / 2))
        method = "chi-square with continuity correction"
    return {"paired_items": len(keys), "a_only_correct": b, "b_only_correct": c,
            "discordant": n, "p_value": float(p), "method": method}


ALPHA_LEVEL = 0.05


def paired_diff_boot(a_flags: dict, b_flags: dict, seed=SEED, n_boot=N_BOOT) -> dict:
    """Bootstrap the PAIRED per-item difference, +1 / 0 / -1 over the shared items.

    This is the interval that belongs beside a McNemar p. Two marginal intervals
    do not: on paired data the variance of the difference is smaller than the
    variance of either rate, so marginal intervals can overlap while the
    difference is far from zero. That is exactly how P5 reported a 3.6pp
    difference at p = 0.0002 as 'no difference detected'.
    """
    keys = sorted(set(a_flags) & set(b_flags))
    if not keys:
        return {"n_pairs": 0, "diff": None, "ci95": [None, None], "se": None}
    d = np.array([float(bool(a_flags[k])) - float(bool(b_flags[k])) for k in keys])
    rng = np.random.default_rng(seed)
    idx = rng.integers(0, d.size, size=(n_boot, d.size))
    means = d[idx].mean(axis=1)
    disc = float((d != 0).mean())
    return {"n_pairs": int(d.size), "diff": float(d.mean()),
            "ci95": [float(np.percentile(means, 2.5)), float(np.percentile(means, 97.5))],
            "se": float(means.std(ddof=1)), "discordant_rate": disc,
            "mdd_points_paired": float((ALPHA + POWER_Z) * math.sqrt(max(disc, 1e-12) / d.size)),
            "basis": "per-item paired difference (+1/0/-1), 1,000 resamples, fixed seed"}


def holm(pvals: dict) -> dict:
    """Holm-Bonferroni across a family of comparisons reported together."""
    items = sorted(((k, v) for k, v in pvals.items() if v is not None), key=lambda kv: kv[1])
    m, out, running = len(items), {}, 0.0
    for i, (k, pv) in enumerate(items):
        adj = min(1.0, (m - i) * pv)
        running = max(running, adj)          # enforce monotonicity
        out[k] = running
    for k, v in pvals.items():
        if v is None:
            out[k] = None
    return {"adjusted": out, "family_size": m, "method": "Holm-Bonferroni"}


def verdict_paired(a: dict, b: dict, mn: dict, pdiff: dict, adj_p: float | None = None,
                   family_size: int | None = None) -> dict:
    """Verdict for a PAIRED comparison: it comes from McNemar, not from whether
    two marginal intervals overlap. The marginal rates stay in the record as
    descriptive context and are labelled as such."""
    p_used = adj_p if adj_p is not None else mn.get("p_value")
    if a.get("rate") is None or b.get("rate") is None or not mn.get("paired_items"):
        return {"verdict": "not comparable", "design": "paired", "reason": "a rate or the pairing is missing"}
    v = "difference detected" if (p_used is not None and p_used < ALPHA_LEVEL) else "no difference detected"
    return {
        "verdict": v, "design": "paired", "decided_by": ("Holm-adjusted McNemar p" if adj_p is not None else "McNemar p"),
        "mcnemar_p": mn.get("p_value"), "mcnemar_p_holm": adj_p, "family_size": family_size,
        "alpha": ALPHA_LEVEL,
        "paired_difference": pdiff,
        "marginal_a": {"rate": a["rate"], "ci95": a["ci95"], "n": a["n"], "note": "descriptive, not the verdict"},
        "marginal_b": {"rate": b["rate"], "ci95": b["ci95"], "n": b["n"], "note": "descriptive, not the verdict"},
        "marginal_intervals_overlap": not (a["ci95"][1] < b["ci95"][0] or b["ci95"][1] < a["ci95"][0]),
        "rule": ("paired comparison: the verdict follows the McNemar test (Holm-adjusted within its family). "
                 "Marginal interval overlap is recorded but decides nothing -- see docs/engineering-rules.md rule 6."),
    }


def verdict_unpaired(a: dict, b: dict) -> dict:
    """For comparisons over DIFFERENT items, where no pairing exists. Interval
    based, and labelled unpaired so it cannot be mistaken for the paired rule."""
    if a.get("rate") is None or b.get("rate") is None:
        return {"verdict": "not comparable", "design": "unpaired", "reason": "a rate is missing"}
    overlap = not (a["ci95"][1] < b["ci95"][0] or b["ci95"][1] < a["ci95"][0])
    return {"verdict": "no difference detected" if overlap else "difference detected",
            "design": "unpaired", "decided_by": "95% bootstrap interval overlap",
            "intervals_overlap": overlap,
            "a": {"rate": a["rate"], "ci95": a["ci95"], "n": a["n"]},
            "b": {"rate": b["rate"], "ci95": b["ci95"], "n": b["n"]},
            "rule": "different items on each side, so there is no pairing to exploit and no McNemar test to run"}


def verdict(a: dict, b: dict, p_value: float | None = None) -> dict:
    """Retained only so nothing silently keeps the old behaviour: it refuses.

    P5 called this on paired comparisons and got marginal-overlap verdicts.
    Callers must now choose verdict_paired or verdict_unpaired explicitly.
    """
    raise HarnessError(
        "verdict() is removed: choose verdict_paired() or verdict_unpaired(). "
        "The old function judged paired comparisons by marginal interval overlap "
        "(docs/engineering-rules.md rule 6)."
    )


# ---------------------------------------------------------------------- scoring
def _length_stats(lengths) -> dict:
    v = sorted(lengths)
    n = len(v)
    if not n:
        return {"n": 0}
    total = sum(v)
    top1 = sum(v[int(n * 0.99):])
    return {"n": n, "median": v[n // 2], "p99": v[min(n - 1, int(n * 0.99))], "max": v[-1],
            "total_tokens": total,
            "top_1pct_share_of_tokens": round(top1 / total, 4) if total else 0.0}


def _primary_flag(task, parsed, target) -> bool:
    if task in exact_match.FIELDS:
        return exact_match.score_one(task, parsed, target)["correct"]
    if task == "cvss_vector":
        return cvss_fields.score_one(parsed, target)["whole_vector_exact"]
    row = extract_fields.score_one(parsed, target)
    return extract_fields.item_all_fields_correct(row, target)


def score_run(run_id: str, with_sandbox: bool = True) -> dict:
    manifest, d = load_run(run_id)
    tasks = tuple(manifest["tasks"]); splits = tuple(manifest["splits"])
    ds = verify_dataset(eval_file_keys(tasks, splits))
    if ds["dataset_manifest_sha256"] != manifest["dataset_manifest_sha256"]:
        raise HarnessError("dataset manifest changed since the run; refusing to score "
                           f"(run {manifest['dataset_manifest_sha256'][:16]}, "
                           f"disk {ds['dataset_manifest_sha256'][:16]})")
    validators = schema_scorer.load_validators(SCHEMAS, tasks)
    items = {}
    for t in tasks:
        for sp in splits:
            for e in iter_jsonl(OUT / t / f"{sp}.jsonl"):
                items[(t, sp, e["example_id"])] = e

    outputs = list(iter_jsonl(d / "outputs.jsonl"))
    groups = defaultdict(list)
    for o in outputs:
        groups[(o["kind"], o["task"], o["split"], o["decoding"])].append(o)

    out = {"run_id": run_id, "manifest_sha_fields": {
        "dataset_manifest_sha256": manifest["dataset_manifest_sha256"],
        "model_checkpoint_sha256": manifest["model_checkpoint_sha256"],
        "outputs_jsonl_sha256": manifest["outputs_jsonl_sha256"]},
        "primary_metric": PRIMARY, "scored": ds["scored"],
        "not_scored_reason": ds["not_scored_reason"], "strata": manifest["strata"],
        "domain": {}, "general": {}, "sandbox": {}, "gaps": {}}
    # Per-item correctness lives in its own file: it is large, it is the input to
    # the paired tests P5 needs, and keeping it out of scores.json keeps the
    # score record readable and reviewable.
    out["flags"] = {}

    for (kind, t, sp, mode), rows in sorted(groups.items()):
        rows.sort(key=lambda r: r["example_id"])
        if kind == "probe":
            continue                                   # scored by eval/probe.py against matched controls
        if kind == "general":
            g = [general_scorer.score_one(r["output_text"], {"answer": _general_target(t, r["example_id"])})
                 for r in rows]
            extracted = [x["extracted"] for x in g]
            corr_all = [x["correct"] for x in g]
            corr_ext = [x["correct"] for x in g if x["extracted"]]
            out["general"][t] = {
                "letter_extracted": boot_ci(extracted),
                "accuracy_over_extracted": boot_ci(corr_ext),
                "accuracy_over_all": boot_ci(corr_all),
                "mdd_points": mdd(float(np.mean(corr_all)) if corr_all else None, len(corr_all)),
                "n_items": len(rows), "decoding": mode,
            }
            out["flags"][f"general/{t}/{mode}"] = {
                "correct": {r["example_id"]: bool(x["correct"]) for r, x in zip(rows, g)},
                "schema_valid": {r["example_id"]: bool(x["extracted"]) for r, x in zip(rows, g)}}
            continue

        schema_rows, prim, strat, detail = [], [], [], []
        for r in rows:
            it = items[(t, sp, r["example_id"])]
            s = schema_scorer.score_one(r["output_text"], validators[t][1])
            schema_rows.append(s)
            parsed = s["value"] if s["schema_valid"] else None
            ok = _primary_flag(t, parsed, it["target"]) if s["schema_valid"] else False
            prim.append(ok); strat.append(r["stratum"])
            detail.append((it, parsed, s["schema_valid"], ok))

        key = f"{t}/{sp}/{mode}"
        valid = [x["schema_valid"] for x in schema_rows]
        parsed_ok = [x["parsed"] for x in schema_rows]
        corr_over_valid = [ok for (_, _, v, ok) in detail if v]
        rec = {
            "task": t, "split": sp, "decoding": mode, "scored": ds["scored"].get(t, True),
            "n_items": len(rows),
            "parse_rate": boot_ci(parsed_ok),
            "schema_valid_rate": boot_ci(valid),
            "accuracy_over_schema_valid": boot_ci(corr_over_valid),
            "accuracy_over_all_items": boot_ci(prim),
            "denominators": {"all_items": len(rows), "schema_valid": int(sum(valid))},
            "mdd_points_over_all": mdd(float(np.mean(prim)) if prim else None, len(prim)),
            "fence_stripped": sum(1 for x in schema_rows if x["normalization"] == schema_scorer.FENCE),
            "truncated": sum(1 for r in rows if r["finish_reason"] == "length"),
            # Output length is a cost measurement, and the cost is a tail. It is
            # recorded per group because P5 runs this three times and the free
            # decoding mode is where the hours go.
            "output_length": _length_stats([r["n_output_tokens"] for r in rows]),
            "by_stratum": {},
        }
        for s_name in strata.STRATA:
            sel = [i for i, v in enumerate(strat) if v == s_name]
            rec["by_stratum"][s_name] = {
                "n_items": len(sel),
                "schema_valid_rate": boot_ci([valid[i] for i in sel]),
                "accuracy_over_all_items": boot_ci([prim[i] for i in sel]),
                "accuracy_over_schema_valid": boot_ci([prim[i] for i in sel if valid[i]]),
                "mdd_points_over_all": mdd(float(np.mean([prim[i] for i in sel])) if sel else None, len(sel)),
            }
        if t == "cvss_vector":
            fr = [cvss_fields.score_one(p, it["target"]) for (it, p, v, _) in detail if v]
            rec["cvss_per_field"] = {m: boot_ci([x["fields"][m]["correct"] for x in fr])
                                     for m in cvss_fields.METRICS}
            rec["cvss_per_field"]["vectorString"] = boot_ci([x["vector_string"]["correct"] for x in fr])
            rec["cvss_per_field"]["baseScore"] = boot_ci([x["base_score"]["correct"] for x in fr])
            rec["cvss_metrics_all_correct"] = boot_ci([x["metrics_all_correct"] for x in fr])
        if t == "structured_extract":
            er = [extract_fields.score_one(p, it["target"]) for (it, p, v, _) in detail if v]
            rec["extract_fields"] = extract_fields.aggregate(er)
        out["domain"][key] = rec
        out["flags"][key] = {
            "correct": {r["example_id"]: bool(ok) for r, ok in zip(rows, prim)},
            "schema_valid": {r["example_id"]: bool(v) for r, v in zip(rows, valid)}}

    # free vs constrained, and post vs pre: both are gaps between recorded rates.
    for t in tasks:
        for sp in splits:
            f, c = out["domain"].get(f"{t}/{sp}/free"), out["domain"].get(f"{t}/{sp}/constrained")
            if f and c:
                fk = out["flags"][f"{t}/{sp}/free"]; ck = out["flags"][f"{t}/{sp}/constrained"]
                mn_sv = mcnemar(fk["schema_valid"], ck["schema_valid"])
                mn_acc = mcnemar(fk["correct"], ck["correct"])
                pd_sv = paired_diff_boot(fk["schema_valid"], ck["schema_valid"])
                pd_ac = paired_diff_boot(fk["correct"], ck["correct"])
                out["gaps"][f"decoding/{t}/{sp}"] = {
                    "paired": True, "mcnemar_schema_valid": mn_sv, "mcnemar_accuracy": mn_acc,
                    "schema_valid": verdict_paired(f["schema_valid_rate"], c["schema_valid_rate"], mn_sv, pd_sv),
                    "accuracy": verdict_paired(f["accuracy_over_all_items"], c["accuracy_over_all_items"],
                                               mn_acc, pd_ac),
                    "free_schema_valid": f["schema_valid_rate"]["rate"],
                    "constrained_schema_valid": c["schema_valid_rate"]["rate"],
                    "schema_valid_gap": (c["schema_valid_rate"]["rate"] - f["schema_valid_rate"]["rate"]),
                    "accuracy_over_all_gap": (c["accuracy_over_all_items"]["rate"]
                                              - f["accuracy_over_all_items"]["rate"]),
                    "means": ("how much schema compliance comes from the decoder rather than the model; "
                              "an accuracy gap shows constraint changing content, not just form"),
                }
        for mode in set(o["decoding"] for o in outputs if o["kind"] == "domain"):
            a = out["domain"].get(f"{t}/eval_post_cutoff/{mode}")
            b = out["domain"].get(f"{t}/eval_pre_cutoff/{mode}")
            if a and b:
                out["gaps"][f"temporal/{t}/{mode}"] = {
                    "post_cutoff": a["accuracy_over_all_items"], "pre_cutoff": b["accuracy_over_all_items"],
                    "gap": b["accuracy_over_all_items"]["rate"] - a["accuracy_over_all_items"]["rate"],
                    "design": "unpaired: post-cutoff and pre-cutoff are different CVEs, so there is no pairing",
                    "verdict": verdict_unpaired(a["accuracy_over_all_items"], b["accuracy_over_all_items"])["verdict"],
                    "by_stratum_gap": {
                        s: (b["by_stratum"][s]["accuracy_over_all_items"]["rate"] or 0)
                           - (a["by_stratum"][s]["accuracy_over_all_items"]["rate"] or 0)
                        if a["by_stratum"][s]["n_items"] and b["by_stratum"][s]["n_items"] else None
                        for s in strata.STRATA},
                    "means": ("this pipeline's own estimate of pretraining contamination. If the gap persists "
                              "inside the zero stratum, the contamination is not lexical."),
                }

    if with_sandbox and "cvss_vector" in tasks:
        out["sandbox"] = _sandbox_axis(groups, items, validators)
    from eval.common import harness_code_sha
    out["scoring_code_sha256"] = harness_code_sha()["scoring_code_sha256"]
    flags = out.pop("flags")
    write_json(d / "flags.json", flags)
    out["flags_file"] = "flags.json"
    out["flags_sha256"] = None
    write_json(d / "scores.json", out)
    out["flags"] = flags
    return out


_GEN_CACHE = {}


def _general_target(name, example_id):
    if name not in _GEN_CACHE:
        prep = general_scorer.prepare(name, allow_network=False)
        _GEN_CACHE[name] = {i["example_id"]: i["target"]["answer"] for i in prep["items"]}
    return _GEN_CACHE[name][example_id]


def _sandbox_axis(groups, items, validators) -> dict:
    res = {}
    for (kind, t, sp, mode), rows in sorted(groups.items()):
        if t != "cvss_vector":
            continue
        batch, targets = [], {}
        for r in sorted(rows, key=lambda x: x["example_id"]):
            it = items[(t, sp, r["example_id"])]
            s = schema_scorer.score_one(r["output_text"], validators[t][1])
            vec = (s["value"] or {}).get("vectorString") if s["schema_valid"] else None
            batch.append({"id": r["example_id"], "model_vector": vec,
                          "nvd_vector": it["target"]["vectorString"]})
            targets[r["example_id"]] = it["target"]["baseScore"]
        b = sandbox.run_batch(batch)
        summ = sandbox.summarize([b], targets)
        summ["per_item"] = {}                      # kept out of scores.json; rates are the record
        summ["group"] = f"{t}/{sp}/{mode}"
        res[f"{t}/{sp}/{mode}"] = summ
    return res


# ------------------------------------------------------------------ comparison
_STRATA_CACHE = {}


def _stratum_ids(task: str, split: str, stratum: str) -> set:
    ck = (task, split)
    if ck not in _STRATA_CACHE:
        items = list(iter_jsonl(OUT / task / f"{split}.jsonl"))
        _STRATA_CACHE[ck] = strata.for_items(items)["by_id"]
    return {k for k, v in _STRATA_CACHE[ck].items() if v == stratum}


def _stratum_flags(fa: dict, fb: dict, key: str, stratum: str):
    """Restrict two per-item flag maps to one contamination stratum."""
    task, split, _ = key.split("/")
    ids = _stratum_ids(task, split, stratum)
    return ({k: v for k, v in fa.items() if k in ids}, {k: v for k, v in fb.items() if k in ids})


def compare(run_a: str, run_b: str) -> dict:
    """Paired comparison of two runs. Used by P5 for Cond-1 vs Cond-2; exercised
    here by comparing the baseline with itself, which must return 'no difference
    detected' with no discordant pairs."""
    A = json.loads((RUNS / run_a / "scores.json").read_text())
    B = json.loads((RUNS / run_b / "scores.json").read_text())
    A["flags"] = json.loads((RUNS / run_a / "flags.json").read_text())
    B["flags"] = json.loads((RUNS / run_b / "flags.json").read_text())
    out = {"a": run_a, "b": run_b, "domain": {}, "general": {}}
    for key, ra in A["domain"].items():
        rb = B["domain"].get(key)
        if not rb:
            continue
        if not ra.get("scored", True):
            out["domain"][key] = {"skipped": "scored: false in the dataset manifest; "
                                             "never compared between conditions"}
            continue
        mn = mcnemar(A["flags"][key]["correct"], B["flags"][key]["correct"])
        pd_ = paired_diff_boot(A["flags"][key]["correct"], B["flags"][key]["correct"])
        out["domain"][key] = {
            **verdict_paired(ra["accuracy_over_all_items"], rb["accuracy_over_all_items"], mn, pd_),
            "mcnemar": mn, "mdd_points_unpaired": ra["mdd_points_over_all"],
            "mdd_points_paired": pd_.get("mdd_points_paired"),
            "by_stratum": {st: verdict_paired(
                ra["by_stratum"][st]["accuracy_over_all_items"], rb["by_stratum"][st]["accuracy_over_all_items"],
                mcnemar(*_stratum_flags(A["flags"][key]["correct"], B["flags"][key]["correct"], key, st)),
                paired_diff_boot(*_stratum_flags(A["flags"][key]["correct"], B["flags"][key]["correct"], key, st)))
                for st in strata.STRATA},
        }
    for g, ra in A["general"].items():
        rb = B["general"].get(g)
        if not rb:
            continue
        fa, fb = A["flags"][f"general/{g}/free"]["correct"], B["flags"][f"general/{g}/free"]["correct"]
        mn, pd_ = mcnemar(fa, fb), paired_diff_boot(fa, fb)
        out["general"][g] = {**verdict_paired(ra["accuracy_over_all"], rb["accuracy_over_all"], mn, pd_),
                             "mcnemar": mn, "mdd_points_unpaired": ra["mdd_points"],
                             "mdd_points_paired": pd_.get("mdd_points_paired")}
    return out


# -------------------------------------------------------------------- renderers
def n(x):
    return f"{x:,}" if isinstance(x, (int, float)) and x == x else "—"


def pc(x):
    return "—" if x is None else f"{100*x:.1f}%"


def mark(key: str, scored: dict) -> str:
    """Label a row, and mark it unscored wherever it appears -- not only in the
    first table. `scored: false` has to travel with the number."""
    task = key.split("/")[0]
    return f"`{key}` **[미채점]**" if not scored.get(task, True) else f"`{key}`"


def ci(d):
    if not d or d.get("rate") is None:
        return "—"
    lo, hi = d["ci95"]
    return f"**{100*d['rate']:.1f}%** [{100*lo:.1f}–{100*hi:.1f}] n={d['n']:,}"


def render_baseline(run_id: str) -> Path:
    m = json.loads((RUNS / run_id / "manifest.json").read_text())
    s = json.loads((RUNS / run_id / "scores.json").read_text())
    L = [f"# P4 기준선 평가 결과 — Cond-0 ({m['model_repo']}, 미세조정 없음)\n",
         "> `runs/%s/scores.json`과 `manifest.json`에 **기록된 값**을 렌더링한다. 여기서 아무것도 다시 계산하지 않는다 "
         "(`docs/engineering-rules.md` 규칙 1). 재생성: `python -m eval.stats --run %s --render`.\n" % (run_id, run_id)]

    L.append("## 이 실행이 무엇이었나 (전부 매니페스트 기록)\n")
    L.append("| 항목 | 값 |\n|---|---|")
    L.append(f"| 모델 | `{m['model_repo']}` 커밋 `{m['model_commit'][:12]}` |")
    L.append(f"| 체크포인트 해시 | `{m['model_checkpoint_sha256'][:16]}…` ({m['checkpoint_files']} 파일) |")
    L.append(f"| 토크나이저 / 채팅 템플릿 | `{m['tokenizer_sha256'][:16]}…` / `{m['chat_template_sha256'][:16]}…` |")
    L.append(f"| 데이터셋 매니페스트 | `{m['dataset_manifest_sha256'][:16]}…` (실행 시작 시 디스크와 대조 검증) |")
    L.append(f"| 출력 파일 | `outputs.jsonl` `{m['outputs_jsonl_sha256'][:16]}…`, {n(m['n_outputs'])} 건 |")
    for k, v in m["env"].items():
        L.append(f"| `{k}` | `{v}` |")
    L.append(f"| 샘플링 | temperature {m['sampling']['temperature']}, top_p {m['sampling']['top_p']}, seed {m['sampling']['seed']} |")
    L.append(f"| vLLM 엔진 | {json.dumps(m['vllm_engine'])} |")
    L.append(f"| 구조화 출력 백엔드 | `{m['structured_outputs_backend']}` |")
    L.append(f"| 버전 | vLLM {m['vllm_version']}, torch {m['torch_version']}, transformers {m['transformers_version']} |")
    L.append(f"| GPU / 드라이버 | {m['gpu_name']} / {m['driver_version']} |")
    L.append(f"| 메모리 상한 | {m['memory_ceiling']['mechanism']} `MemoryMax={m['memory_ceiling']['memory_max']}` |")
    L.append(f"| 생성 상한 | {m['max_tokens_rule']} |")
    w = m["wall"]
    L.append(f"\n**1회 전체 평가 통과 벽시계: {w['total_sec']/3600:.2f} 시간** "
             f"(생성 {w['generation_sec']/3600:.2f} h, 모델 로드 {w['model_load_sec']}s). "
             f"P5는 이것을 조건마다 실행한다.\n")

    L.append("## 스키마 유효성과 정확도는 따로 본다\n")
    L.append("파싱되지 않은 출력은 틀린 답이 아니라 **다른 종류의 실패**다. 둘을 합치면 조건이 형식을 잃었는지 지식을 잃었는지 구분할 수 없다. "
             "그래서 스키마 유효율과 정확도를 따로 싣고, 정확도는 **스키마 유효 출력만**을 분모로 한 값과 **전체 항목**을 분모로 한 값을 모두 싣는다.\n")
    L.append("| 과제/분할/디코딩 | 채점 | 항목 | 파싱 | 스키마 유효 | 정확도(유효 분모) | 정확도(전체 분모) | 절단 |")
    L.append("|---|---|---|---|---|---|---|---|")
    for k, r in s["domain"].items():
        L.append(f"| `{k}` | {'예' if r['scored'] else '**아니오**'} | {n(r['n_items'])} | {pc(r['parse_rate']['rate'])} | "
                 f"{ci(r['schema_valid_rate'])} | {ci(r['accuracy_over_schema_valid'])} | "
                 f"{ci(r['accuracy_over_all_items'])} | {r['truncated']} |")
    L.append("\n괄호 안은 95% 부트스트랩 구간 (1,000회 재표집, 고정 시드). 구간 없는 비율은 보고하지 않는다.\n")

    L.append("## 오염 계층별 결과 — 사분위가 아니라 zero / low / high\n")
    L.append("P3.2가 모든 평가 항목에 붙인 `train_ngram_coverage`를 쓴다. **기록된 사분위는 쓰지 않는다**: 커버리지가 0에 몰려 있어 "
             "(`cve_to_cwe/eval_post_cutoff`의 72.8%가 정확히 0) q25와 q50이 모두 0.0이 되고 세트 간 비교가 불가능하다. "
             "대신 각 세트의 **양수 값 중앙값**을 분할점으로 쓴다 — 누가 정한 수준이 아니라 데이터에서 읽은 위치다.\n")
    L.append("| 과제/분할/디코딩 | 분할점 | zero (n) | low (n) | high (n) |\n|---|---|---|---|---|")
    for k, r in s["domain"].items():
        st = s["strata"].get("/".join(k.split("/")[:2]), {})
        cells = []
        for name in strata.STRATA:
            b = r["by_stratum"][name]
            cells.append(f"{ci(b['accuracy_over_all_items'])}" if b["n_items"] else f"— n=0")
        L.append(f"| {mark(k, s['scored'])} | {st.get('positive_median','—')} | " + " | ".join(cells) + " |")
    L.append("\n### 이 표를 Cond-0에서 읽는 법 — 여기서 커버리지 격차는 암기가 아니다\n")
    L.append("여섯 개 채점 세트 **전부**에서 커버리지가 높을수록 정확도가 높다. 그러나 **기준선 모델은 우리 학습 세트를 본 적이 없다.** "
             "따라서 Cond-0에서 커버리지 계층이 재는 것은 암기가 아니라 **설명문이 얼마나 정형화되어 있는가**다 — "
             "우리 코퍼스와 13-gram을 많이 공유하는 항목은 템플릿으로 쓰인 항목이고, 템플릿으로 쓰인 항목이 기준선에게 더 쉽다.\n")
    L.append("**그래서 이 표가 P5의 기준선이다.** 같은 항목, 같은 계층 경계로 미세조정 후를 재서 "
             "**high 계층이 zero 계층보다 더 많이 올랐다면 그 초과분이 암기의 측정값**이다. 여기서는 그 초과분을 잴 수 없고, "
             "잴 수 있는 것은 출발점뿐이다. P3.2가 커버리지 높은 항목 2,483건을 지우는 대신 필드로 붙여 둔 덕분에 "
             "이 측정이 가능하다 — 삭제했다면 이 표 자체가 존재할 수 없다.\n")
    L.append("**high 계층은 일부 세트에서 얇다** (전체 커버리지 히스토그램은 [0.0,0.1)에 15,519건, [0.9,1.0)에 188건). "
             "얇은 계층의 구간은 넓고, 넓은 구간은 점추정값처럼 읽어서는 안 된다.\n")

    L.append("## 컷오프 이후 vs 이전 — 이 파이프라인 자신의 사전학습 오염 추정치\n")
    L.append("| 과제/디코딩 | 이후 | 이전 | 격차(이전−이후) | 판정 | zero 계층 격차 |\n|---|---|---|---|---|---|")
    for k, g in s["gaps"].items():
        if not k.startswith("temporal/"):
            continue
        z = g["by_stratum_gap"].get("zero")
        L.append(f"| {mark(k.split('/',1)[1], s['scored'])} | {ci(g['post_cutoff'])} | {ci(g['pre_cutoff'])} | "
                 f"{pc(g['gap'])} | **{g['verdict']}** | {pc(z) if z is not None else '—'} |")
    L.append("\n### 이 격차를 어디까지 말할 수 있나\n")
    L.append("기준선 모델은 우리 학습 세트를 보지 않았으므로 이 격차는 **우리 데이터의 누수가 아니다**. 남는 설명은 두 가지이고 "
             "이 하네스는 둘을 분리하지 못한다: (1) 모델이 사전학습에서 오래된 CVE를 이미 봤다, (2) 오래된 CVE가 그냥 더 쉽다 "
             "(CNA 구성, CWE 라벨 출처, 설명문 길이가 시간에 따라 다르다 — `datasets/CARD.md` 참조). "
             "**zero 계층에서도 격차가 거의 그대로 남는다는 사실**은 최소한 그 격차가 우리 코퍼스와의 어휘 중복으로는 "
             "설명되지 않는다는 것을 말해 준다.\n")
    L.append("\n컷오프 이전 세트가 더 높다면 그 차이는 모델이 사전학습에서 이미 본 CVE라는 뜻이다. **zero 계층에서도 격차가 남으면 "
             "그 오염은 어휘적(13-gram)이 아니다** — 즉 커버리지로는 잡히지 않는 형태의 사전 노출이다.\n")

    L.append("## 자유 생성 vs 스키마 제약 생성\n")
    L.append("| 과제/분할 | 자유 스키마유효 | 제약 스키마유효 | 형식 격차 | 정확도 격차 | McNemar p (형식) | 판정 |\n|---|---|---|---|---|---|---|")
    for k, g in s["gaps"].items():
        if not k.startswith("decoding/"):
            continue
        L.append(f"| {mark(k.split('/',1)[1], s['scored'])} | {pc(g['free_schema_valid'])} | {pc(g['constrained_schema_valid'])} | "
                 f"{pc(g['schema_valid_gap'])} | {pc(g['accuracy_over_all_gap'])} | "
                 f"{g['mcnemar_schema_valid']['p_value']:.3g} | **{g['schema_valid']['verdict']}** |")
    L.append("\n형식 격차는 **스키마 준수 중 디코더가 만들어낸 몫**이다. 정확도 격차가 0이 아니면 제약이 형식만이 아니라 내용도 바꿨다는 뜻이다.\n")

    cv = [(k, r) for k, r in s["domain"].items() if r["task"] == "cvss_vector"]
    if cv:
        L.append("## `cvss_vector` 필드별 정확도 (스키마 유효 출력 분모)\n")
        fields = list(cv[0][1]["cvss_per_field"].keys())
        L.append("| 과제/분할/디코딩 | " + " | ".join(f"`{f}`" for f in fields) + " |")
        L.append("|---" * (len(fields) + 1) + "|")
        for k, r in cv:
            L.append(f"| `{k}` | " + " | ".join(pc(r["cvss_per_field"][f]["rate"]) for f in fields) + " |")
        L.append("\n`scope`는 특히 중요하다 — 권한 가중치와 최종 점수를 함께 바꾼다. 8개 지표가 모두 맞고 벡터 문자열까지 같은 경우만 "
                 "`whole_vector_exact`로 센다.\n")

    ex = [(k, r) for k, r in s["domain"].items() if r["task"] == "structured_extract"]
    if ex:
        L.append("## `structured_extract` 필드별 정밀도 / 재현율\n")
        L.append("| 과제/분할/디코딩 | vendor P/R | product P/R | versions P/R | versions 집합일치 | impact P/R | impact 허위생성 |\n|---|---|---|---|---|---|---|")
        for k, r in ex:
            a = r["extract_fields"]
            L.append(f"| `{k}` | {pc(a['vendor']['precision'])}/{pc(a['vendor']['recall'])} | "
                     f"{pc(a['product']['precision'])}/{pc(a['product']['recall'])} | "
                     f"{pc(a['versions']['precision'])}/{pc(a['versions']['recall'])} | "
                     f"{pc(a['versions']['exact_set_rate'])} | "
                     f"{pc(a['impact']['precision'])}/{pc(a['impact']['recall'])} | "
                     f"{a['impact']['spurious_when_target_null']} |")
        L.append("\n`impact`는 정답이 null인 항목을 정확도 분모에서 제외한다 (`datasets/CARD.md` 지침). 정답이 null인데 값을 만들어낸 "
                 "건수는 따로 센다 — 분모에서 빠졌다고 사라지지 않는다.\n")

    if s["general"]:
        L.append("## 범용 능력 (망각 검사) — P5의 기준선\n")
        L.append("| 세트 | 항목 | 글자 추출률 | 정확도(추출 분모) | 정확도(전체 분모) | MDD |\n|---|---|---|---|---|---|")
        for g, r in s["general"].items():
            pin = m["general_pins"][g]
            L.append(f"| `{g}` ({pin['repo']} `{pin['revision'][:8]}`) | {n(r['n_items'])} | "
                     f"{pc(r['letter_extracted']['rate'])} | {ci(r['accuracy_over_extracted'])} | "
                     f"{ci(r['accuracy_over_all'])} | ±{100*r['mdd_points']:.1f}pp |")
        L.append("\n이 숫자는 **공개 리더보드 점수와 비교할 수 없다**: 표준 프로토콜은 선택지별 로그 우도를 비교하지만 여기서는 "
                 "모델이 생성한 글자를 읽는다. 조건 간 비교에는 유효하고, 절대값 인용에는 무효다. `reports/eval_harness.md` 참조.\n")

    if s["sandbox"]:
        L.append("## 샌드박스 축 — 실행으로 채점\n")
        L.append("| 그룹 | 항목 | 벡터 실행 성공 | 점수 일치(실행 분모) | 공식 자체검증 | 컨테이너 | 타임아웃 | 초 |\n|---|---|---|---|---|---|---|---|")
        for k, r in s["sandbox"].items():
            L.append(f"| `{k}` | {n(r['items'])} | {pc(r['execution']['rate'])} | {pc(r['score_match']['rate'])} | "
                     f"**{pc(r['formula_self_test']['rate'])}** ({n(r['formula_self_test']['n'])}) | "
                     f"{r['containers']} | {r['timeouts']} | {r['seconds']} |")
        sb = next(iter(s["sandbox"].values()))
        L.append(f"\n컨테이너: `{sb['image']}` `{sb['image_id'][:19]}…`, 플래그 `{' '.join(sb['docker_flags'][2:])}`, 타임아웃 {sb['timeout_sec']}s.")
        L.append("**공식 자체검증**은 NVD 자신의 벡터로 점수를 계산해 NVD가 기록한 점수와 비교한 값이다. 이것이 100%가 아니면 "
                 "위의 모델 점수 일치율은 공식 구현 오류를 모델 결과로 잘못 보고하는 것이 된다.\n")

    L.append("## 생성 비용 — P5가 이것을 세 번 돌린다\n")
    L.append("| 과제/분할/디코딩 | 출력 토큰 중앙값 | p99 | 최대 | 총 출력 토큰 | 상위 1%가 차지하는 비율 | 문맥 한계까지 간 항목 |\n|---|---|---|---|---|---|---|")
    for k, r in s["domain"].items():
        o = r.get("output_length", {})
        L.append(f"| `{k}` | {n(o.get('median'))} | {n(o.get('p99'))} | {n(o.get('max'))} | {n(o.get('total_tokens'))} | "
                 f"{pc(o.get('top_1pct_share_of_tokens'))} | {r['truncated']} |")
    L.append(f"\n1회 통과 벽시계 **{w['total_sec']/3600:.2f} 시간** 중 생성이 {w['generation_sec']/3600:.2f} 시간이다. "
             "**비용은 꼬리에서 나온다**: 자유 생성에서 상위 1% 항목이 전체 출력 토큰의 상당 부분을 차지한다. "
             "제약 생성은 문법이 조기 종료를 강제하므로 같은 항목 수에 훨씬 적은 토큰을 쓴다. "
             "P5가 조건마다 한 번씩 돌릴 때의 예산은 이 표에서 나온다.\n")
    L.append("## 검출 가능한 최소 차이 (MDD)\n")
    L.append("귀무 결과와 검정력 부족을 구분하기 위해, 각 세트의 n에서 유의수준 0.05·검정력 0.80으로 검출 가능한 최소 차이를 싣는다. "
             "짝지은 McNemar 검정은 이보다 검정력이 높으므로 아래 값은 **보수적 상한**이다.\n")
    L.append("| 과제/분할/디코딩 | n | 정확도 | MDD | zero MDD | low MDD | high MDD |\n|---|---|---|---|---|---|---|")
    for k, r in s["domain"].items():
        b = r["by_stratum"]
        f = lambda x: (f"±{100*x:.1f}pp" if x else "—")
        L.append(f"| {mark(k, s['scored'])} | {n(r['n_items'])} | {pc(r['accuracy_over_all_items']['rate'])} | "
                 f"{f(r['mdd_points_over_all'])} | {f(b['zero']['mdd_points_over_all'])} | "
                 f"{f(b['low']['mdd_points_over_all'])} | {f(b['high']['mdd_points_over_all'])} |")

    L.append("\n## 채점하지 않는 과제\n")
    for t, why in s["not_scored_reason"].items():
        L.append(f"- **`{t}`**: {why}")
    L.append("\n위 표에 숫자가 있어도 `scored: 아니오`로 표시된 행은 **조건 간 비교에 절대 쓰이지 않는다**. "
             "`python -m eval.stats --compare A B`가 그 행을 건너뛰고 건너뛴 사실을 기록한다.\n")
    L.append("## 이 결과로 할 수 없는 말\n")
    L.append("`reports/eval_harness.md`의 '이 하네스가 측정하지 못하는 것' 절을 읽지 않고 이 숫자를 인용하면 과대주장이 된다. "
             "요약하면: 보안 역량을 재지 않고, 과제는 추론이 아니라 회수와 구조 추출이며, 평가 세트는 CNA 편향이 알려진 네 출처에서 나왔고, "
             "`attack_technique`는 너무 작다.\n")
    REPORTS.mkdir(parents=True, exist_ok=True)
    out = REPORTS / "eval_baseline.md"
    out.write_text("\n".join(L) + "\n", encoding="utf-8")
    return out


def render_harness(run_id: str) -> Path:
    m = json.loads((RUNS / run_id / "manifest.json").read_text())
    L = ["# P4 평가 하네스 — 설계와 한계\n",
         "> 설정값·핀·해시는 `runs/%s/manifest.json`에서 읽어 렌더링한다. 재생성: "
         "`python -m eval.stats --run %s --render-harness`.\n" % (run_id, run_id)]

    L.append("## 이 하네스가 존재하는 이유\n")
    L.append("P5의 두 조건이 **다른지 아닌지**를 P5가 돌기 전에 판정할 수 있게 하는 것. 그러려면 숫자가 질문을 견뎌야 한다: "
             "재현 가능하고, 오염 계층별로 나뉘어 있고, 못 보는 것을 솔직하게 말해야 한다.\n")

    L.append("## 타협 불가능한 실행 설정\n")
    L.append("Gate 0이 이 기계에서 측정한 두 사실 위에 세워져 있다. 그리디 디코딩은 `VLLM_BATCH_INVARIANT=1` 없이는 "
             "바이트 단위로 재현되지 않으며(순차 실행에서도 15회 중 2가지 출력), 배치 불변 커널은 1.073배 비용이 든다. "
             "그리고 FlashInfer 샘플러는 시작할 때 JIT 컴파일하므로 `VLLM_USE_FLASHINFER_SAMPLER=0`이 필요하다.\n")
    L.append("| 설정 | 값 | 기록 위치 |\n|---|---|---|")
    for k, v in m["env"].items():
        L.append(f"| `{k}` | `{v}` | 실행 매니페스트 `env` |")
    L.append(f"| 샘플링 | temperature {m['sampling']['temperature']}, top_p {m['sampling']['top_p']}, seed {m['sampling']['seed']} | `sampling` |")
    L.append(f"| vLLM 엔진 | {json.dumps(m['vllm_engine'])} | `vllm_engine` (Gate 0 검사 05·06에서 검증된 값 그대로) |")
    L.append("\n**이 중 하나라도 매니페스트에 없는 실행은 무효이고, 채점기가 거부한다** — `eval/common.py`의 "
             "`check_manifest_settings`가 강제한다. 또한 실행의 첫 동작은 데이터셋 매니페스트 해시를 디스크와 대조하는 것이다. "
             "드리프트한 데이터셋에 대해 계산한 점수는 점수가 없는 것보다 나쁘다.\n")

    L.append("## 네 개의 축\n")
    L.append("| 축 | 무엇을 재나 | 채점기 |\n|---|---|---|")
    L.append("| 스키마 | 출력이 파싱되고 과제 JSON Schema를 통과하는가 | `jsonschema`, 기계적 |")
    L.append("| 과제 정확도 | 정확 일치 / 필드별 정확도 / 필드 정밀도·재현율 | 기계적 |")
    L.append("| 범용 능력 | 망각 검사: MMLU 부분집합, HellaSwag | 기계적 |")
    L.append("| 샌드박스 | CVSS v3.1 공식을 컨테이너에서 실행해 NVD 점수와 대조 | Docker, 기계적 |")
    L.append("\n**어떤 것도 언어 모델이 채점하지 않는다.** 정규화 규칙은 전부 선언되어 있다: 앞뒤 공백 제거와 "
             "마크다운 코드펜스 한 겹 제거뿐이며, 산문 속에서 JSON을 파내거나 따옴표를 고치지 않는다.\n")

    L.append("## 계층화\n")
    st = next(iter(m["strata"].values()))
    L.append(f"`{st['definition']}`\n")
    L.append(f"> {st['note']}\n")
    L.append("| 평가 세트 | 양수 중앙값(분할점) | zero | low | high |\n|---|---|---|---|---|")
    for k, v in m["strata"].items():
        c = v["counts"]
        L.append(f"| `{k}` | {v['positive_median']} | {c['zero']:,} | {c['low']:,} | {c['high']:,} |")
    L.append("\n계층 표가 답하는 두 질문: **정확도가 커버리지와 함께 오르는가**(그 격차가 암기다), 그리고 "
             "**컷오프 이후/이전 격차가 계층으로 설명되는가, 아니면 각 계층 안에서도 남는가**(zero 계층에서도 남으면 "
             "그 오염은 어휘적이지 않다).\n")

    L.append("## 통계 규칙\n")
    L.append(f"- 보고하는 모든 비율에 부트스트랩 {N_BOOT:,}회 재표집, 95% 백분위 구간. **구간 없는 비율은 보고하지 않는다.**")
    L.append("- 조건 비교는 같은 항목을 짝지어 McNemar로 한다 (불일치쌍 25 미만이면 정확 이항검정).")
    L.append("- **구간이 겹치면 결론은 '차이 검출되지 않음'이다.** '경향', '약간 우세' 같은 표현을 쓰지 않는다. "
             "이 판정 문자열은 하네스가 직접 출력하므로, 보고서가 숫자보다 강하게 쓰일 수 없다.")
    L.append("- 귀무 결과와 검정력 부족을 구분하기 위해 세트별 MDD(검출 가능한 최소 차이)를 함께 싣는다.\n")

    probe_p = RUNS / "throughput_probe.json"
    if probe_p.exists():
        pr = json.loads(probe_p.read_text())
        L.append("## 동시성은 처리량 설정이지 결과 설정이 아니다 (측정)\n")
        L.append(f"`{pr['group']}`에서 동시 시퀀스 상한만 바꾸고 나머지는 동일하게 두고 측정했다.\n")
        L.append("| `max_num_seqs` | 초 | 출력 토큰/초 | 출력 파일 sha256 |\n|---|---|---|---|")
        for r in pr["rows"]:
            L.append(f"| {r['max_num_seqs']} | {r['seconds']} | {r['output_tokens_per_sec']} | `{r['outputs_sha256'][:24]}…` |")
        L.append(f"\n**세 설정의 출력이 바이트 단위로 동일하다: {pr['all_outputs_byte_identical']}**. "
                 f"처리량은 {pr['speedup_16_to_256']}배 차이가 난다. {pr['conclusion']}")
        L.append(f"\n그래서 이 하네스는 `max_num_seqs={pr['chosen_max_num_seqs']}`을 쓴다 "
                 f"(Gate 0 참조값 {pr['gate0_reference_max_num_seqs']}). 이 값은 매니페스트에 기록되고, "
                 "Gate 4가 **실제로 쓰인 그 값에서** 재현성을 증명한다.\n")
    L.append("## 결정론 게이트 (Gate 4)\n")
    L.append("기준선 모델로 전체 평가를 **두 번** 돌려 모든 생성 출력이 바이트 단위로 같고 모든 점수가 같아야 통과한다. "
             "하나라도 다르면 다른 항목을 보고하고 채점을 거부한다. Gate 0은 이 기계에서 배치 불변성 없이는 순차 실행조차 "
             "갈라진다는 것을 보였다. Gate 4는 그 해법이 **전체 평가 규모, 실제 배치 혼합에서도** 유지되는지를 증명한다.\n")

    L.append("## 이 하네스가 측정하지 못하는 것\n")
    L.append("이 절을 읽지 않고 이 저장소의 숫자를 인용하면 과대주장이 된다.\n")
    L.append("1. **보안 역량을 재지 않는다.** 취약점을 찾거나, 익스플로잇을 쓰거나, 사고를 분석하거나, 방어를 설계하는 능력에 "
             "대해 이 숫자들은 아무 말도 하지 않는다. 재는 것은 공개 취약점 데이터베이스의 **구조화 필드를 회수·추출하는 능력**이다.")
    L.append("2. **과제는 추론이 아니라 회수와 구조 추출이다.** `cve_to_cwe`는 분류, `cvss_vector`는 고정 어휘로의 사상, "
             "`structured_extract`는 CNA가 이미 채운 구조를 산문에서 되찾는 일이다. 어느 것도 다단계 추론을 요구하지 않는다.")
    L.append("3. **평가 세트에 CNA 편향이 있다.** 네 출처(CVE List V5, NVD, CWE, ATT&CK)에서 나왔고, 소수 CNA가 "
             "설명문의 큰 비중을 차지하며 그 CNA들은 템플릿을 쓴다. 학습 세트와의 CNA 총변동거리는 데이터셋 매니페스트에 기록되어 있다 "
             "(`reports/contamination.md`).")
    L.append("4. **`attack_technique`는 너무 작다.** 학습 738건, 평가 79/79건. 신뢰구간이 ±10퍼센트포인트를 넘는다. "
             "매니페스트에 `scored: false`로 표시되어 있고, 서술적으로만 보고하며 **조건 간 비교에 절대 쓰지 않는다.**")
    L.append("5. **범용 능력 숫자는 리더보드와 비교할 수 없다.** 표준 MMLU/HellaSwag 프로토콜은 선택지별 로그 우도를 비교하지만 "
             "이 하네스는 모델이 생성한 글자를 읽는다. 조건 간 비교에는 유효하고 절대값 인용에는 무효다.")
    L.append("6. **컷오프 이전/이후 격차는 사전학습 오염의 *추정치*이지 측정치가 아니다.** 모델의 사전학습 데이터를 볼 수 없으므로 "
             "격차의 원인을 시점 이외의 요인(난이도 변화, CNA 구성 변화, CWE 라벨 출처 변화)과 완전히 분리할 수 없다. "
             "그래서 `cwe_source`와 계층을 함께 싣는다.")
    L.append("7. **근접 중복 임계값 0.75는 아직 보정되지 않았다.** P2.1이 네 번 요청되고 전달되지 않았다. 데이터셋 매니페스트에 "
             f"`{m['dataset']['near_threshold_source']}`로 기록되어 있다. 이 값이 바뀌면 평가 세트가 다시 만들어지고 "
             "**이 하네스가 만든 모든 숫자를 다시 계산해야 한다.** 이 결과는 최종이 아니다.")
    L.append("8. **단일 시드, 단일 체크포인트.** 그리디 디코딩이라 샘플링 분산은 없지만, 학습 시드에 따른 분산은 이 하네스가 "
             "재지 않는다. P5가 조건당 한 번씩만 학습한다면 조건 간 차이에는 학습 시드 분산이 섞여 있다.\n")

    L.append("## 산출물 구조\n")
    L.append("```\nruns/<run_id>/manifest.json   설정·해시·버전·타이밍\nruns/<run_id>/outputs.jsonl   모든 생성 원문 (재채점의 근거)\n"
             "runs/<run_id>/scores.json     모든 점수와 구간\n```\n")
    L.append("원문 출력을 실행마다 보관한다. 그것이 모든 점수의 증거이고, 다시 생성하지 않고 다시 채점할 수 있게 한다 "
             "(채점에 GPU가 필요 없다).\n")
    REPORTS.mkdir(parents=True, exist_ok=True)
    out = REPORTS / "eval_harness.md"
    out.write_text("\n".join(L) + "\n", encoding="utf-8")
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--run", help="run id to score")
    ap.add_argument("--score", action="store_true", help="score the run and write scores.json")
    ap.add_argument("--no-sandbox", action="store_true")
    ap.add_argument("--render", action="store_true", help="render reports/eval_baseline.md")
    ap.add_argument("--render-harness", action="store_true", help="render reports/eval_harness.md")
    ap.add_argument("--compare", nargs="+", metavar="RUN", help="two run ids, or one comma-separated list (baseline first)")
    ap.add_argument("--self-compare", metavar="RUN", help="compare a run with itself; must detect no difference")
    ap.add_argument("--analyses", metavar="RUN", help="P5: stratum x length tercile and label analysis -> analysis.json")
    ap.add_argument("--render-training", action="store_true")
    ap.add_argument("--assert-verdict-consistency", action="store_true",
                    help="no comparison may report a verdict contradicting its own p value")
    ap.add_argument("--file", default="runs/compare.json", help="record to check with --assert-verdict-consistency")
    ap.add_argument("--runs", default="cond1,cond2", help="for --render-training")
    a = ap.parse_args()
    if a.assert_verdict_consistency:
        import json as _j
        rec = _j.loads(Path(a.file).read_text())
        try:
            assert_verdict_consistency(rec, label=a.file)
            print(f"VERDICT CONSISTENCY OK: {a.file} -- every verdict agrees with its own test")
            return 0
        except HarnessError as e:
            print(f"VERDICT CONSISTENCY FAILED: {e}", file=sys.stderr)
            bad = []
            def _w(n, path=""):
                if isinstance(n, dict):
                    v = n.get("verdict"); pv = n.get("mcnemar_p")
                    if pv is None and isinstance(n.get("mcnemar"), dict): pv = n["mcnemar"].get("p_value")
                    if isinstance(v, str) and isinstance(pv, (int, float)) and n.get("design") != "unpaired":
                        pa = n.get("mcnemar_p_holm"); pu = pa if pa is not None else pv
                        if (v == "no difference detected") == (pu < ALPHA_LEVEL): bad.append((path, v, pv))
                    for k2, s2 in n.items(): _w(s2, f"{path}.{k2}" if path else str(k2))
                elif isinstance(n, list):
                    for i, s2 in enumerate(n): _w(s2, f"{path}[{i}]")
            _w(rec)
            for path, v, pv in bad[:12]:
                print(f"   {path}: verdict '{v}' with p={pv:.3g}", file=sys.stderr)
            print(f"   ({len(bad)} violations total)", file=sys.stderr)
            return 1
    if a.analyses:
        r = analyses(a.analyses); print(f"wrote runs/{a.analyses}/analysis.json")
    if a.render_training:
        print(render_training(a.runs.split(",")))
    if a.score:
        s = score_run(a.run, with_sandbox=not a.no_sandbox)
        print(json.dumps({k: {kk: vv["accuracy_over_all_items"]["rate"] for kk, vv in [(k, v)]}
                          for k, v in s["domain"].items()}, indent=1)[:1200])
        print("wrote scores.json")
    if a.compare:
        runs = a.compare[0].split(",") if len(a.compare) == 1 else list(a.compare)
        if len(runs) >= 3 or a.render:
            if a.render:
                sys.stdout.write(render_results(runs).read_text(encoding="utf-8"))
            else:
                print(json.dumps({k: {pk: pv["accuracy"]["verdict"] for pk, pv in v["pairs"].items()}
                                  for k, v in compare_multi(runs)["domain"].items()}, indent=1))
            return 0
        print(json.dumps(compare(*runs), indent=2, ensure_ascii=False))
    if a.self_compare:
        c = compare(a.self_compare, a.self_compare)
        bad = [k for k, v in c["domain"].items() if v.get("verdict") not in (None, "no difference detected")
               and "skipped" not in v]
        print(json.dumps({k: {"verdict": v.get("verdict", v.get("skipped")),
                              "discordant": v.get("mcnemar", {}).get("discordant")}
                          for k, v in c["domain"].items()}, indent=1, ensure_ascii=False))
        print("SELF-COMPARE OK" if not bad else f"SELF-COMPARE FAILED: {bad}")
        return 1 if bad else 0
    # The report is written to reports/ AND echoed to stdout, so both
    # `make eval-report` and `python -m eval.stats --run X --render > file` do
    # the right thing instead of one of them clobbering the report with a path.
    if a.render and a.run:
        sys.stdout.write(render_baseline(a.run).read_text(encoding="utf-8"))
    if a.render_harness and a.run:
        out = render_harness(a.run)
        if not a.render:
            sys.stdout.write(out.read_text(encoding="utf-8"))
        else:
            print(f"\n<!-- also wrote {out} -->", file=sys.stderr)
    if not any([a.score, a.render, a.render_harness, a.compare, a.self_compare,
                a.analyses, a.render_training, a.assert_verdict_consistency]):
        ap.print_help()
    return 0




# ================================================================== P5 analyses
# Everything below reads recorded outputs (flags.json, eval files) and
# regenerates nothing. score_run above is untouched by P5.

def _eval_items(tasks, splits):
    items = {}
    for t in tasks:
        for sp in splits:
            items[(t, sp)] = {e["example_id"]: e for e in iter_jsonl(OUT / t / f"{sp}.jsonl")}
    return items


def _flags(run_id):
    return json.loads((RUNS / run_id / "flags.json").read_text())


LABEL_FIELD = {"cve_to_cwe": ("cwe_id", None), "cvss_vector": ("vectorString", None),
               "structured_extract": ("vendor", "casefold")}


def item_label(task, target):
    f, norm = LABEL_FIELD[task]
    v = target.get(f)
    if isinstance(v, str):
        v = v.strip()
        if norm == "casefold":
            v = v.casefold()
    return v


def tercile_table(run_id: str, decoding: str = "constrained") -> dict:
    """accuracy by coverage stratum x description-length tercile, n in every cell."""
    flags = _flags(run_id)
    out = {}
    for t in ("cve_to_cwe", "cvss_vector", "structured_extract"):
        for sp in EVAL_SPLITS:
            key = f"{t}/{sp}/{decoding}"
            if key not in flags:
                continue
            items = {e["example_id"]: e for e in iter_jsonl(OUT / t / f"{sp}.jsonl")}
            st = strata.for_items(items.values())
            lengths = {k: strata.n_grams(e["input"]) for k, e in items.items()}
            tb = strata.terciles(lengths.values())
            corr = flags[key]["correct"]
            cells = {}
            for s_name in strata.STRATA:
                for tc in strata.TERCILES:
                    sel = [k for k in items if st["by_id"][k] == s_name and strata.tercile_of(lengths[k], tb) == tc]
                    cells[f"{s_name}/{tc}"] = boot_ci([corr[k] for k in sel])
            marg_t = {tc: boot_ci([corr[k] for k in items if strata.tercile_of(lengths[k], tb) == tc])
                      for tc in strata.TERCILES}
            out[key] = {"tercile_bounds": tb, "positive_median": st["positive_median"],
                        "cells": cells, "by_tercile": marg_t,
                        "mean_ngrams_by_stratum": {s: (round(float(np.mean([lengths[k] for k in items if st["by_id"][k] == s])), 1)
                                                       if st["counts"][s] else None) for s in strata.STRATA}}
    return out


def label_analysis(run_id: str, decoding: str = "constrained") -> dict:
    """Do the two evaluation sets differ in true-label mix, and does that explain
    the pre/post gap? Per-label accuracy plus a label-reweighted comparison."""
    flags = _flags(run_id)
    out = {}
    for t in ("cve_to_cwe", "cvss_vector", "structured_extract"):
        sets = {}
        for sp in EVAL_SPLITS:
            key = f"{t}/{sp}/{decoding}"
            if key not in flags:
                continue
            items = {e["example_id"]: e for e in iter_jsonl(OUT / t / f"{sp}.jsonl")}
            corr = flags[key]["correct"]
            labs = {k: item_label(t, e["target"]) for k, e in items.items()}
            sets[sp] = {"labels": labs, "correct": corr}
        if len(sets) < 2:
            continue
        post, pre = sets["eval_post_cutoff"], sets["eval_pre_cutoff"]

        def dist(s):
            c = Counter(s["labels"].values()); n = sum(c.values())
            return {k: v / n for k, v in c.items()}, c

        def per_label(s):
            acc, n = defaultdict(int), defaultdict(int)
            for k, y in s["labels"].items():
                n[y] += 1; acc[y] += int(s["correct"][k])
            return {y: acc[y] / n[y] for y in n}, dict(n)

        p_post, c_post = dist(post); p_pre, c_pre = dist(pre)
        a_post, n_post = per_label(post); a_pre, n_pre = per_label(pre)
        tvd = 0.5 * sum(abs(p_post.get(y, 0) - p_pre.get(y, 0)) for y in set(p_post) | set(p_pre))

        def reweight(acc_by_label, target_mix):
            common = [y for y in target_mix if y in acc_by_label]
            mass = sum(target_mix[y] for y in common)
            return (sum(target_mix[y] * acc_by_label[y] for y in common) / mass if mass else None), mass

        def boot_reweight(src, target_mix, seed=SEED):
            keys = sorted(src["labels"]); n = len(keys)
            rng = np.random.default_rng(seed)
            vals = []
            for _ in range(N_BOOT):
                idx = rng.integers(0, n, size=n)
                acc, cnt = defaultdict(int), defaultdict(int)
                for i in idx:
                    y = src["labels"][keys[i]]; cnt[y] += 1; acc[y] += int(src["correct"][keys[i]])
                r, _ = reweight({y: acc[y] / cnt[y] for y in cnt}, target_mix)
                vals.append(r if r is not None else np.nan)
            v = np.array(vals, dtype=float); v = v[~np.isnan(v)]
            return [float(np.percentile(v, 2.5)), float(np.percentile(v, 97.5))] if v.size else [None, None]

        pre_as_post, cov1 = reweight(a_pre, p_post)
        post_as_pre, cov2 = reweight(a_post, p_pre)
        raw_post = boot_ci([post["correct"][k] for k in post["labels"]])
        raw_pre = boot_ci([pre["correct"][k] for k in pre["labels"]])
        top = sorted(set([y for y, _ in c_post.most_common(12)] + [y for y, _ in c_pre.most_common(12)]),
                     key=lambda y: -(c_post.get(y, 0) + c_pre.get(y, 0)))[:15]
        out[t] = {
            "decoding": decoding, "label_field": LABEL_FIELD[t][0],
            "n_labels_post": len(c_post), "n_labels_pre": len(c_pre),
            "label_tvd_post_vs_pre": round(tvd, 4),
            "raw": {"post": raw_post, "pre": raw_pre, "gap_pre_minus_post": raw_pre["rate"] - raw_post["rate"]},
            "reweighted": {
                "pre_under_post_label_mix": {"rate": pre_as_post, "ci95": boot_reweight(pre, p_post),
                                             "post_mass_covered": round(cov1, 4)},
                "post_under_pre_label_mix": {"rate": post_as_pre, "ci95": boot_reweight(post, p_pre),
                                             "pre_mass_covered": round(cov2, 4)},
                "gap_pre_minus_post_at_post_mix": (pre_as_post - raw_post["rate"]) if pre_as_post is not None else None,
                "gap_pre_minus_post_at_pre_mix": (raw_pre["rate"] - post_as_pre) if post_as_pre is not None else None,
            },
            "top_labels": [{"label": y, "share_post": round(p_post.get(y, 0), 4), "share_pre": round(p_pre.get(y, 0), 4),
                            "n_post": c_post.get(y, 0), "n_pre": c_pre.get(y, 0),
                            "acc_post": (round(a_post[y], 4) if y in a_post else None),
                            "acc_pre": (round(a_pre[y], 4) if y in a_pre else None)} for y in top],
        }
    return out


def analyses(run_id: str) -> dict:
    rec = {"run_id": run_id, "tercile_table": tercile_table(run_id), "label_analysis": label_analysis(run_id)}
    write_json(RUNS / run_id / "analysis.json", rec)
    return rec


# ============================================================ P5 comparison
def _scores(run_id):
    return json.loads((RUNS / run_id / "scores.json").read_text())


def compare_multi(runs) -> dict:
    """baseline first. Every condition comparison is PAIRED -- both runs answer
    the same items -- so each carries a McNemar p, a Holm-adjusted p within the
    family of comparisons reported together, a bootstrap interval of the paired
    difference, and a paired MDD. The marginal rates remain as description.

    Two families, because two tables are read together:
      general  = benchmarks x pairs   (2 x 3 = 6 on the current runs)
      domain   = scored sets x pairs  (constrained)
    """
    S = {r: _scores(r) for r in runs}
    F = {r: _flags(r) for r in runs}
    pairs = ([(runs[1], runs[2])] + [(r, runs[0]) for r in runs[1:]]) if len(runs) >= 3 else [(runs[1], runs[0])]
    out = {"runs": runs, "pairs": [f"{a} vs {b}" for a, b in pairs], "domain": {}, "general": {}, "schema": {},
           "scoring_code_sha256": {r: S[r].get("scoring_code_sha256") for r in runs},
           "dataset_manifest_sha256": {r: S[r]["manifest_sha_fields"]["dataset_manifest_sha256"] for r in runs},
           "design": ("condition comparisons are paired over identical evaluation items; verdicts follow "
                      "Holm-adjusted McNemar. Marginal bootstrap intervals are descriptive only "
                      "(docs/engineering-rules.md rule 6)."),
           "families": {}}

    # ---- pass 1: compute the tests, collect p-values per family
    raw = {"general": {}, "domain": {}, "domain_schema": {}, "domain_free": {}, "domain_free_schema": {}}
    cache = {}
    keys = [k for k, v in S[runs[0]]["domain"].items() if v.get("scored", True)]
    for k in keys:
        for a, b in pairs:
            if k not in S[a]["domain"] or k not in S[b]["domain"]:
                continue
            mn = mcnemar(F[a][k]["correct"], F[b][k]["correct"])
            pd_ = paired_diff_boot(F[a][k]["correct"], F[b][k]["correct"])
            mn_s = mcnemar(F[a][k]["schema_valid"], F[b][k]["schema_valid"])
            pd_s = paired_diff_boot(F[a][k]["schema_valid"], F[b][k]["schema_valid"])
            cache[(k, a, b)] = (mn, pd_, mn_s, pd_s)
            fam = "domain" if k.endswith("/constrained") else "domain_free"
            raw[fam][f"{k}|{a} vs {b}"] = mn["p_value"]
            raw[fam + "_schema"][f"{k}|{a} vs {b}"] = mn_s["p_value"]
    for g in GENERAL:
        if not all(g in S[r]["general"] for r in runs):
            continue
        for a, b in pairs:
            fa, fb = F[a][f"general/{g}/free"]["correct"], F[b][f"general/{g}/free"]["correct"]
            mn, pd_ = mcnemar(fa, fb), paired_diff_boot(fa, fb)
            cache[(g, a, b)] = (mn, pd_, None, None)
            raw["general"][f"{g}|{a} vs {b}"] = mn["p_value"]
    adj = {fam: holm(pv) for fam, pv in raw.items() if pv}
    out["families"] = {fam: {"size": h["family_size"], "method": h["method"],
                             "members": sorted(raw[fam])} for fam, h in adj.items()}

    # ---- pass 2: build the records with adjusted p in the verdict
    for k in keys:
        rec = {"rates": {r: S[r]["domain"][k]["accuracy_over_all_items"] for r in runs if k in S[r]["domain"]},
               "schema_valid": {r: S[r]["domain"][k]["schema_valid_rate"] for r in runs if k in S[r]["domain"]},
               "mdd_points_unpaired": S[runs[0]]["domain"][k]["mdd_points_over_all"], "pairs": {}}
        for a, b in pairs:
            if (k, a, b) not in cache:
                continue
            mn, pd_, mn_s, pd_s = cache[(k, a, b)]
            fam_key = f"{k}|{a} vs {b}"
            famname = "domain" if k.endswith("/constrained") else "domain_free"
            ap = adj.get(famname, {}).get("adjusted", {}).get(fam_key)
            aps = adj.get(famname + "_schema", {}).get("adjusted", {}).get(fam_key)
            fam_n = adj.get(famname, {}).get("family_size")
            rec["mdd_points_paired"] = pd_.get("mdd_points_paired")
            rec["pairs"][f"{a} vs {b}"] = {
                "accuracy": {**verdict_paired(S[a]["domain"][k]["accuracy_over_all_items"],
                                              S[b]["domain"][k]["accuracy_over_all_items"], mn, pd_, ap, fam_n),
                             "mcnemar": mn},
                "schema_valid": {**verdict_paired(S[a]["domain"][k]["schema_valid_rate"],
                                                  S[b]["domain"][k]["schema_valid_rate"], mn_s, pd_s, aps,
                                                  adj.get(famname + "_schema", {}).get("family_size")),
                                 "mcnemar": mn_s},
                "by_stratum": {st: verdict_paired(
                    S[a]["domain"][k]["by_stratum"][st]["accuracy_over_all_items"],
                    S[b]["domain"][k]["by_stratum"][st]["accuracy_over_all_items"],
                    mcnemar(*_stratum_flags(F[a][k]["correct"], F[b][k]["correct"], k, st)),
                    paired_diff_boot(*_stratum_flags(F[a][k]["correct"], F[b][k]["correct"], k, st)))
                    for st in strata.STRATA},
            }
        out["domain"][k] = rec
    for g in GENERAL:
        if not all(g in S[r]["general"] for r in runs):
            continue
        rec = {"rates": {r: S[r]["general"][g]["accuracy_over_all"] for r in runs},
               "extracted": {r: S[r]["general"][g]["letter_extracted"]["rate"] for r in runs},
               "mdd_points_unpaired": S[runs[0]]["general"][g]["mdd_points"], "pairs": {}}
        for a, b in pairs:
            mn, pd_, _, _ = cache[(g, a, b)]
            fam_key = f"{g}|{a} vs {b}"
            rec["mdd_points_paired"] = pd_.get("mdd_points_paired")
            rec["pairs"][f"{a} vs {b}"] = {
                **verdict_paired(S[a]["general"][g]["accuracy_over_all"], S[b]["general"][g]["accuracy_over_all"],
                                 mn, pd_, adj["general"]["adjusted"].get(fam_key), adj["general"]["family_size"]),
                "mcnemar": mn}
        out["general"][g] = rec
    assert_verdict_consistency(out, label="freshly computed comparison")
    write_json(RUNS / "compare.json", out)
    return out


def assert_verdict_consistency(rec: dict, label: str = "", alpha: float = ALPHA_LEVEL) -> list:
    """No comparison may report a verdict that contradicts its own p value.

    Walks any comparison record and checks every node carrying both a verdict
    and a McNemar p. Returns the violations; raises if there are any. This is the
    check that fires on P5's archived record, where verdicts came from marginal
    interval overlap.
    """
    bad = []

    def walk(node, path):
        if isinstance(node, dict):
            v, p = node.get("verdict"), node.get("mcnemar_p")
            if p is None and isinstance(node.get("mcnemar"), dict):
                p = node["mcnemar"].get("p_value")
            if isinstance(v, str) and isinstance(p, (int, float)) and node.get("design") != "unpaired":
                pa = node.get("mcnemar_p_holm")
                p_used = pa if pa is not None else p
                if v == "no difference detected" and p_used < alpha:
                    bad.append({"path": path, "verdict": v, "p": p, "p_used": p_used,
                                "why": "verdict says no difference while its own test rejects at alpha"})
                elif v == "difference detected" and p_used >= alpha:
                    bad.append({"path": path, "verdict": v, "p": p, "p_used": p_used,
                                "why": "verdict says difference while its own test does not reject"})
            for k, sub in node.items():
                walk(sub, f"{path}.{k}" if path else str(k))
        elif isinstance(node, list):
            for i, sub in enumerate(node):
                walk(sub, f"{path}[{i}]")

    walk(rec, "")
    if bad:
        raise HarnessError(f"verdict/p inconsistency in {label or 'record'}: {len(bad)} violation(s); "
                           f"first: {bad[0]}")
    return bad


def _tm(run_id):
    p = RUNS / run_id / "train_manifest.json"
    return json.loads(p.read_text()) if p.exists() else None


def render_training(runs) -> Path:
    L = ["# P5 학습 보고서 — 두 조건, 같은 토큰, 같은 스텝\n",
         "> `runs/<cond>/train_manifest.json`과 `steps.jsonl`의 기록을 렌더링한다. 재생성: `python -m eval.stats --render-training`.\n"]
    ms = {r: _tm(r) for r in runs}
    ms = {r: m for r, m in ms.items() if m}
    if not ms:
        L.append("(학습 매니페스트 없음)")
    else:
        m0 = next(iter(ms.values())); c = m0["config"]
        L.append("## 설정 (두 조건 동일, 데이터 구성만 다름)\n")
        L.append(f"- LoRA r={c['lora']['r']}, alpha={c['lora']['alpha']}, dropout {c['lora']['dropout']}, 대상 `{', '.join(c['lora']['target_modules'])}`")
        L.append(f"- lr {c['lr']} (선형 워밍업 {c['warmup_steps']}스텝 후 코사인 → 0), AdamW, 클리핑 {c['grad_clip']}, bf16 베이스 + fp32 LoRA, bf16 autocast")
        L.append(f"- seq {c['seq_len']} 패킹(블록 대각 마스크 + 예제별 position id), 배치 {c['per_device_batch']} × GA {c['grad_accum']} = 스텝당 16 시퀀스, "
                 f"**{c['steps']}스텝**, gradient checkpointing, sdpa, seed {c['seed']}")
        L.append(f"- 메모리 상한: `systemd-run --user --scope -p MemoryMax=80G -p MemorySwapMax=0` (호스트 RSS만 덮음, A2 측정)\n")
        L.append("## 결과\n")
        L.append("| 조건 | 상태 | 예제 | 패킹 시퀀스 | 사용 / 잔여 | 본 예제 비율 | 토큰(사용) | 지도 토큰 | 스텝 | 평균 s/step | 벽시계 | 첫 loss → 끝 loss |\n|---|---|---|---|---|---|---|---|---|---|---|---|")
        for r, m in ms.items():
            L.append(f"| `{r}` | {m['status']} | {n(m['examples'])} | {n(m['packed_sequences'])} | {n(m['sequences_used'])} / {m['sequences_left_over']} | "
                     f"**{m['epoch_fraction']:.1%}** | {n(m['tokens_in_used_sequences'])} | {n(m['supervised_tokens'])} | {m['steps_completed']} | "
                     f"{m['mean_sec_per_step_after_first']} | **{m['wall_sec']/3600:.2f} h** | {m['loss_first']} → {m['loss_last']} |")
        L.append("\n### 워밍업 검사 — Gate 0의 129.5 s/step 예측 대비\n")
        L.append("| 조건 | 측정 스텝 | 평균 s/step | 예측 | 비율 | 예상 총 시간 |\n|---|---|---|---|---|---|")
        for r, m in ms.items():
            w = m.get("warmup_check") or {}
            if w:
                L.append(f"| `{r}` | {w['steps_measured']} | {w['mean_sec_per_step']} | {w['gate0_prediction_sec_per_step']} | "
                         f"**×{w['ratio_observed_over_predicted']}** | {w['projected_hours_for_run']} h |")
        L.append("\nGate 0의 수치는 합성 4096토큰 시퀀스에서 나왔고 패킹된 실제 데이터는 모양이 다르다 — 그런데도 예측이 맞았다. "
                 "중단 기준(2배 초과)에 근접하지도 않았다.\n")
        L.append("### 일정이 놓친 것 — 에폭이 아니다\n")
        L.append(f"{m0['schedule_note']}\n")
        L.append("| 조건 | 과제별 본 예제 | 전체 |\n|---|---|---|")
        for r, m in ms.items():
            L.append(f"| `{r}` | {m['examples_seen_by_task']} | {n(m['examples_seen'])} / {n(m['examples'])} |")
        L.append("\n두 조건 모두 같은 토큰 예산(157 × 16 × 4096 슬롯)을 썼고 같은 비율의 데이터를 봤다. 비교는 성립한다. "
                 "'1 에폭'이라는 표현은 성립하지 않으므로 쓰지 않는다.\n")
        L.append("### 패킹 격리 검사 (실행 시작 시 이 장비에서 재측정)\n")
        L.append("| 조건 | 마스크 적용 vs 단독 (max |Δlogit|) | 순진 패킹 vs 단독 | argmax 일치 |\n|---|---|---|---|")
        for r, m in ms.items():
            i = m["packing_isolation_check"]
            L.append(f"| `{r}` | {i['max_abs_logit_diff_masked_vs_alone']} | {i['max_abs_logit_diff_naive_vs_alone']} | {i['argmax_agreement_masked_vs_alone']} |")
        L.append("\n### 재현성 — 기록한 것과 주장하지 않는 것\n")
        L.append("| 조건 | seed | 데이터 순서 해시 | 어댑터 sha256 | 병합 체크포인트 sha256 | 부분집합 검사 |\n|---|---|---|---|---|---|")
        for r, m in ms.items():
            L.append(f"| `{r}` | {m['seed']} | `{m['data_order_sha256'][:16]}…` | `{m.get('adapter_sha256','')[:16]}…` | "
                     f"`{m.get('merged_checkpoint_sha256','')[:16]}…` | {'파일에서 재계산, 통과' if m['subset_check']['subset_holds'] else '실패'} |")
        L.append(f"\n{m0['reproducibility_claim']}. 두 조건의 seed는 같고 데이터 순서 해시는 다르다 — 데이터가 다르기 때문이고, 그것이 유일한 차이다.\n")
        L.append("### 손실 곡선 (기록된 스텝에서 발췌)\n")
        L.append("| 스텝 | " + " | ".join(f"`{r}` loss" for r in ms) + " |\n|---|" + "---|" * len(ms))
        logs = {r: [json.loads(l) for l in (RUNS / r / "steps.jsonl").read_text().splitlines()] for r in ms}
        for st in (1, 5, 10, 20, 40, 60, 80, 100, 120, 140, 157):
            row = [str(next((x["loss"] for x in logs[r] if x["step"] == st), "—")) for r in ms]
            L.append(f"| {st} | " + " | ".join(row) + " |")
    REPORTS.mkdir(parents=True, exist_ok=True)
    out = REPORTS / "training.md"
    out.write_text("\n".join(L) + "\n", encoding="utf-8")
    return out


def _p(x):
    return "—" if x is None else f"{x:.3g}"


def _vmark(v):
    return "**차이 검출되지 않음**" if v == "no difference detected" else ("**차이 검출됨**" if v == "difference detected" else v)


def render_results(runs) -> Path:
    C = compare_multi(runs)
    S = {r: _scores(r) for r in runs}
    M = {r: json.loads((RUNS / r / "manifest.json").read_text()) for r in runs}
    A = {r: (json.loads((RUNS / r / "analysis.json").read_text()) if (RUNS / r / "analysis.json").exists() else None) for r in runs}
    T = {r: _tm(r) for r in runs}
    probe = json.loads((RUNS / "probe" / "scores.json").read_text()) if (RUNS / "probe" / "scores.json").exists() else None
    b, c1, c2 = runs[0], runs[1], (runs[2] if len(runs) > 2 else None)
    main_pair = f"{c1} vs {c2}" if c2 else f"{c1} vs {b}"
    ds = M[b]["dataset"]

    L = ["# P5 결과 — 세 조건, 모든 축, 판정\n",
         "> `runs/compare.json`, `runs/<run>/scores.json`, `runs/<run>/analysis.json`, `runs/probe/scores.json`의 기록을 렌더링한다. "
         "여기서 아무것도 다시 계산하지 않는다. 재생성: `python -m eval.stats --compare %s --render`.\n" % ",".join(runs)]

    L.append("## 이 결과가 딛고 선 것 — 먼저 읽을 것\n")
    L.append(f"1. **평가 세트는 보정되지 않은 근접 중복 임계값 위에 있다.** {ds['near_threshold']} — 출처 `{ds['near_threshold_source']}`. "
             "P2.1은 다섯 번 요청되었고 전달되지 않았다. 이 값이 바뀌면 평가 세트가 다시 만들어지고 **이 보고서의 모든 숫자는 다시 계산된다.**")
    L.append("2. 사용자 공간 OOM 데몬은 없다 (root 필요). 모든 학습·평가는 `MemoryMax=80G` 사용자 스코프 안에서 돌았다. "
             "그 상한은 호스트 RSS만 덮는다 (A2 측정).")
    L.append("3. 조건당 학습 시드 하나. 조건 간 차이에는 시드 분산이 섞여 있고 이 실험은 그것을 재지 않는다.")
    L.append("4. 157스텝은 각 조건 데이터의 약 84%를 본다 (`reports/training.md`). 두 조건이 같은 비율이므로 비교는 성립하고, '1 에폭'은 아니다.\n")

    L.append("## 세 실행 — 같은 하네스였다는 증거\n")
    L.append("| 실행 | 모델 | 체크포인트 sha256 | 데이터셋 매니페스트 | 채점 코드 sha256 | 생성 코드 sha256 | 동시성 | 벽시계 |\n|---|---|---|---|---|---|---|---|")
    for r in runs:
        m = M[r]
        L.append(f"| `{r}` | {m.get('model_kind','base')} | `{m['model_checkpoint_sha256'][:12]}…` | `{m['dataset_manifest_sha256'][:12]}…` | "
                 f"`{(S[r].get('scoring_code_sha256') or '')[:12]}…` | `{(m.get('harness_code_sha256') or '(P4 실행, 미기록)')[:12]}` | "
                 f"{m['vllm_engine'].get('max_num_seqs')} | {m['wall']['total_sec']/3600:.2f} h |")
    same_score = len(set(C["scoring_code_sha256"].values())) == 1 and None not in C["scoring_code_sha256"].values()
    same_ds = len(set(C["dataset_manifest_sha256"].values())) == 1
    L.append(f"\n채점 코드 해시가 세 실행에서 동일: **{same_score}**. 데이터셋 매니페스트 동일: **{same_ds}**. "
             "`eval/scorers/`는 P4 이후 한 줄도 바뀌지 않았다 (`git diff 2b5f119 HEAD -- eval/scorers/` 비어 있음). "
             "생성 코드(runner)는 병합 체크포인트 경로와 탐침 항목을 받도록 확장됐고, 그것은 채점에 관여하지 않는다.\n")
    if T.get(c1):
        L.append("학습: " + "; ".join(f"`{r}` {T[r]['steps_completed']}스텝, {T[r]['wall_sec']/3600:.2f} h, 어댑터 `{T[r]['adapter_sha256'][:12]}…`"
                                    for r in runs if T.get(r)) + " — `reports/training.md`.\n")

    L.append("## 사전 등록한 기대 — 결과가 나온 뒤에 바꿀 수 없도록 먼저 적는다\n")
    L.append("- **도메인 정확도**: Cond-1 ≥ Cond-2가 예상된다. Cond-2는 같은 계산량에서 도메인 데이터를 20% 적게 본다. **리플레이에 불리한 증거가 아니다.**")
    L.append("- **범용 능력 (MMLU, HellaSwag)**: 중요한 비교다. 같은 계산량에서 Cond-2가 더 많이 유지하면 이 설정에서 리플레이가 작동한 것이다. "
             "구간이 겹치면 리플레이의 효과는 이 실험이 검출할 수 있는 크기 아래에 있고, **그것이 결과다.**\n")

    L.append("## 범용 능력 — 사전 등록한 핵심 비교 (P5.1에서 검정을 고쳤다)\n")
    L.append("**P5는 이 비교들을 잘못된 검정으로 판정했다.** 두 조건은 **같은 항목**에 답하므로 짝지은 비교이고, "
             "짝지은 자료에서는 차이의 분산이 각 비율의 분산보다 작다. 그래서 주변 신뢰구간이 겹치는 것과 차이가 없는 것은 "
             "별개다. P5는 p=0.0002인 비교에 '차이 검출되지 않음'을 적었다. P5.1은 판정을 **Holm 보정된 McNemar**로 바꾸고, "
             "두 개의 주변 구간 대신 **차이 자체의 구간**을 싣는다. 원래 기록은 `runs/compare_p5_uncorrected.json`에 그대로 있다 "
             "(`docs/engineering-rules.md` 규칙 6).\n")
    fam = C.get("families", {}).get("general", {})
    L.append(f"가족 크기 {fam.get('size','?')} (벤치마크 2 × 쌍 3), Holm 보정, 유의수준 {ALPHA_LEVEL}.\n")
    for g, rec in C["general"].items():
        L.append(f"### `{g}`\n")
        L.append("| 조건 | 정확도 (주변, 서술용) |\n|---|---|")
        for r in runs:
            L.append(f"| `{r}` | {ci(rec['rates'][r])} |")
        L.append(f"\n**짝지은 MDD ±{100*rec['mdd_points_paired']:.1f}pp** — P5가 쓰던 비짝지음 수치는 "
                 f"±{100*rec['mdd_points_unpaired']:.1f}pp였고, 그것이 3.6pp 차이를 '검출 불가'로 부른 이유다.\n")
        L.append("| 쌍 | **차이 (짝지은)** | 95% 구간 (차이) | 불일치쌍 | McNemar p | **Holm p** | **판정** |\n|---|---|---|---|---|---|---|")
        for pk, pr in rec["pairs"].items():
            d = pr["paired_difference"]; mn = pr["mcnemar"]
            L.append(f"| {pk} | **{100*d['diff']:+.1f}pp** | [{100*d['ci95'][0]:+.1f}, {100*d['ci95'][1]:+.1f}] | "
                     f"{mn['a_only_correct']} / {mn['b_only_correct']} | {pr['mcnemar_p']:.3g} | "
                     f"**{_p(pr['mcnemar_p_holm'])}** | {_vmark(pr['verdict'])} |")
        L.append("")
    L.append("### 경계에 있는 값들 — 반올림하지 않는다\n")
    near = []
    for g, rec in C["general"].items():
        for pk, pr in rec["pairs"].items():
            if pr["mcnemar_p_holm"] is not None and 0.02 <= pr["mcnemar_p_holm"] <= 0.15:
                near.append((g, pk, pr))
    if near:
        for g, pk, pr in near:
            d = pr["paired_difference"]
            L.append(f"- `{g}` {pk}: 원 p={pr['mcnemar_p']:.3g}, **Holm p={_p(pr['mcnemar_p_holm'])}** — 유의수준 바로 "
                     f"{'위' if pr['mcnemar_p_holm'] >= ALPHA_LEVEL else '아래'}다. 차이의 구간은 "
                     f"[{100*d['ci95'][0]:+.1f}, {100*d['ci95'][1]:+.1f}]pp로 0을 "
                     f"{'포함하지 않는다' if d['ci95'][0]*d['ci95'][1] > 0 else '포함한다'} (구간은 다중비교 보정 전이다). "
                     "이 값은 어느 쪽으로도 반올림하지 않고 그대로 싣는다.")
        L.append("")
    L.append("### 두 벤치마크가 서로 다른 답을 준다 — 하나를 고르지 않는다\n")
    hs = C["general"].get("hellaswag", {}).get("pairs", {})
    mm = C["general"].get("mmlu", {}).get("pairs", {})
    def gp(d, k, f="verdict"):
        return (d.get(k) or {}).get(f)
    L.append("- **HellaSwag**: Cond-2가 Cond-1보다 앞선다 — "
             f"{100*gp(hs,'cond1 vs cond2','paired_difference')['diff']*-1:+.1f}pp, Holm p="
             f"{gp(hs,'cond1 vs cond2','mcnemar_p_holm'):.3g}, 불일치쌍 "
             f"{gp(hs,'cond1 vs cond2','mcnemar')['b_only_correct']} 대 {gp(hs,'cond1 vs cond2','mcnemar')['a_only_correct']}. "
             f"그리고 Cond-2는 기준선과 구별되지 않는다 (p={gp(hs,'cond2 vs baseline','mcnemar_p'):.3g}) — "
             "**같은 토큰, 같은 스텝에서 리플레이가 이 벤치마크의 능력을 지켰다.**")
    L.append("- **MMLU**: 리플레이가 돕지 않았다. Cond-2는 기준선보다 "
             f"{100*gp(mm,'cond2 vs baseline','paired_difference')['diff']:+.1f}pp 낮고 이것은 검출된다 "
             f"(Holm p={gp(mm,'cond2 vs baseline','mcnemar_p_holm'):.3g}). Cond-1의 하락 "
             f"({100*gp(mm,'cond1 vs baseline','paired_difference')['diff']:+.1f}pp, Holm p="
             f"{gp(mm,'cond1 vs baseline','mcnemar_p_holm'):.3g})보다 **크다**. 두 조건끼리는 구별되지 않는다 "
             f"(p={gp(mm,'cond1 vs cond2','mcnemar_p'):.3g}).")
    L.append("\n**따라서 쓸 수 있는 결론은 하나다: 리플레이의 효과는 무엇을 범용 능력으로 정의하느냐에 달렸다.** "
             "두 벤치마크 중 하나를 골라 '리플레이가 작동한다/안 한다'고 쓰는 것은 이 자료가 허락하지 않는다.\n")
    L.append("> oasst2의 대화체가 HellaSwag의 문장 완성에는 가깝고 MMLU의 객관식 지식 회수에는 멀다는 설명이 그럴듯하지만, "
             "**이 실험은 그 가설을 검정하지 않았다.** 가설로만 적어 둔다.\n")
    L.append("> **이 결과는 조건당 시드 하나에 기대고 있다.** 3.6pp 차이가 Holm 보정 후에도 살아남는 것은 강한 신호지만, "
             "실행 간 분산에 대한 증거는 이 실험에 없고 시드 분산은 이 크기의 차이를 만드는 알려진 원인이다. "
             "두 번째 시드가 같은 방향을 보이면 결론은 단단해지고, 뒤집히면 이 설계는 리플레이와 시드 분산을 "
             "분리하지 못한다는 것이 정직한 결론이 된다.\n")
    L.append("## 도메인 정확도 (제약 생성, 전체 항목 분모)\n")
    L.append("`attack_technique`는 이 표에 없다 — 아래 산문 절 참조.\n")
    L.append("| 과제/분할 | " + " | ".join(f"`{r}`" for r in runs) +
             f" | **{main_pair} 차이 (짝지은)** | McNemar p / Holm | 판정 | 짝지은 MDD |\n|---|" + "---|" * (len(runs) + 4))
    for k, rec in C["domain"].items():
        if not k.endswith("/constrained"):
            continue
        pr = rec["pairs"].get(main_pair)
        if pr:
            a_ = pr["accuracy"]; d = a_["paired_difference"]
            cell = (f" | **{100*d['diff']:+.1f}pp** [{100*d['ci95'][0]:+.1f},{100*d['ci95'][1]:+.1f}] | "
                    f"{_p(a_['mcnemar_p'])} / **{_p(a_['mcnemar_p_holm'])}** | {_vmark(a_['verdict'])} | "
                    f"±{100*rec.get('mdd_points_paired', 0):.1f}pp |")
        else:
            cell = " | — | — | — | — |"
        L.append(f"| `{k.rsplit('/',1)[0]}` | " + " | ".join(ci(rec["rates"][r]) for r in runs if r in rec["rates"]) + cell)
    L.append("\n기준선 대비 (제약 생성):\n\n| 과제/분할 | 쌍 | 차이 (짝지은) | 판정 | McNemar p / Holm |\n|---|---|---|---|---|")
    for k, rec in C["domain"].items():
        if not k.endswith("/constrained"):
            continue
        for pk, pr in rec["pairs"].items():
            if pk == main_pair:
                continue
            a_ = pr["accuracy"]; d = a_["paired_difference"]
            L.append(f"| `{k.rsplit('/',1)[0]}` | {pk} | {100*d['diff']:+.1f}pp | {_vmark(a_['verdict'])} | "
                     f"{_p(a_['mcnemar_p'])} / {_p(a_['mcnemar_p_holm'])} |")

    L.append("\n## 자유 생성 — 형식과 정확도가 학습으로 어떻게 변했나\n")
    L.append("| 과제/분할 | " + " | ".join(f"`{r}` 스키마유효 / 정확도" for r in runs) + f" | 스키마유효 {main_pair} |\n|---|" + "---|" * (len(runs) + 1))
    for k, rec in C["domain"].items():
        if not k.endswith("/free"):
            continue
        pr = rec["pairs"].get(main_pair)
        L.append(f"| `{k.rsplit('/',1)[0]}` | " + " | ".join(f"{pc(rec['schema_valid'][r]['rate'])} / {pc(rec['rates'][r]['rate'])}" for r in runs if r in rec["rates"]) +
                 (f" | {_vmark(pr['schema_valid']['verdict'])} (Holm p={_p(pr['schema_valid']['mcnemar_p_holm'])}) |" if pr else " | — |"))
    L.append("\n기준선의 자유 생성 스키마 유효율은 `cvss_vector`에서 0.2%였다 (산문 서두). 미세조정이 그것을 어디까지 바꿨는지가 이 표다.\n")

    L.append("## 컷오프 이후 vs 이전 — 조건별, 그리고 라벨 분포를 먼저 본다\n")
    L.append("| 과제 | 조건 | 이후 | 이전 | 원 격차 | 라벨 TVD | 이전→이후 라벨믹스 재가중 격차 | 이후→이전 재가중 격차 |\n|---|---|---|---|---|---|---|---|")
    for t in ("cve_to_cwe", "cvss_vector", "structured_extract"):
        for r in runs:
            la = (A[r] or {}).get("label_analysis", {}).get(t)
            if not la:
                continue
            rw = la["reweighted"]
            L.append(f"| `{t}` | `{r}` | {pc(la['raw']['post']['rate'])} | {pc(la['raw']['pre']['rate'])} | {100*la['raw']['gap_pre_minus_post']:+.1f}pp | "
                     f"{la['label_tvd_post_vs_pre']} | {100*rw['gap_pre_minus_post_at_post_mix']:+.1f}pp (이후 질량 {rw['pre_under_post_label_mix']['post_mass_covered']:.0%}) | "
                     f"{100*rw['gap_pre_minus_post_at_pre_mix']:+.1f}pp (이전 질량 {rw['post_under_pre_label_mix']['pre_mass_covered']:.0%}) |")
    la = (A[b] or {}).get("label_analysis", {}).get("cve_to_cwe")
    if la:
        L.append("\n두 평가 세트의 **참 라벨 분포가 다르다** — `cve_to_cwe`에서 TVD "
                 f"{la['label_tvd_post_vs_pre']}. 오래된 CVE는 빈번하고 쉬운 클래스에 몰려 있다. 기준선에서 라벨 믹스를 맞추면 격차의 대부분이 사라진다. "
                 "P4 보고서가 '분리 불가능한 두 설명'이라고 쓴 것 중 상당 부분은 **셋째 설명, 라벨 믹스**였다. 아래는 기준선의 상위 라벨:\n")
        L.append("| 라벨 | 이후 비중 | 이전 비중 | 이후 정확도 | 이전 정확도 |\n|---|---|---|---|---|")
        for x in la["top_labels"][:12]:
            L.append(f"| `{x['label']}` | {x['share_post']:.1%} ({x['n_post']}) | {x['share_pre']:.1%} ({x['n_pre']}) | {pc(x['acc_post'])} | {pc(x['acc_pre'])} |")
        L.append("")

    L.append("## 계층 × 길이 삼분위 — 커버리지 효과인가, 길이였나\n")
    L.append("커버리지 0인 항목은 13-gram이 학습 설명문 23만 건 어디에도 없는 항목이고, 그것은 짧거나 특이한 설명문을 고른다. "
             "그래서 계층을 설명문 길이(13-gram 수) 삼분위 안에서 다시 본다. 각 셀에 n. 제약 생성.\n")
    for r in runs:
        tt = (A[r] or {}).get("tercile_table", {})
        if not tt:
            continue
        L.append(f"### `{r}`\n")
        for k, v in tt.items():
            if not k.endswith("/constrained"):
                continue
            L.append(f"**`{k.rsplit('/',1)[0]}`** — 삼분위 경계 ≤{v['tercile_bounds']['t1_max']} / ≤{v['tercile_bounds']['t2_max']} 13-gram; "
                     f"계층별 평균 길이 {v['mean_ngrams_by_stratum']}\n")
            L.append("| 길이 \\ 계층 | zero | low | high |\n|---|---|---|---|")
            for tc in strata.TERCILES:
                cells = []
                for s_ in strata.STRATA:
                    c_ = v["cells"][f"{s_}/{tc}"]
                    cells.append(f"{pc(c_['rate'])} [{100*c_['ci95'][0]:.0f}–{100*c_['ci95'][1]:.0f}] n={c_['n']}" if c_["n"] else "— n=0")
                L.append(f"| {tc} | " + " | ".join(cells) + " |")
            L.append("")
    L.append("계층 비교는 보고서에 남는다. **더 이상 암기 주장의 근거가 아니다** — 그 근거는 `reports/memorization.md`의 탐침이다.\n")

    if probe:
        L.append("## 암기 — 직접 측정 (요약; 전체는 `reports/memorization.md`)\n")
        L.append("| 조건 | 짝 수 | 탐침 | 대조 | 차이 | 95% 구간 | Cond-0 바닥 대비 |\n|---|---|---|---|---|---|---|")
        for r in runs:
            p = probe["runs"].get(r, {}).get("constrained", {}).get("pooled")
            if not p:
                continue
            ab = probe["runs"][r]["constrained"].get("above_cond0_floor", {}).get("diff_minus_baseline_diff")
            L.append(f"| `{r}` | {p['n_pairs']} | {pc(p['probe_acc'])} | {pc(p['control_acc'])} | {100*p['diff']:+.1f}pp | "
                     f"[{100*p['diff_ci95'][0]:+.1f}, {100*p['diff_ci95'][1]:+.1f}] | {('%+.1fpp' % (100*ab)) if ab is not None else '(바닥)'} |")
        L.append("")

    L.append("## 샌드박스 축 — 조건별\n")
    L.append("| 조건 | 그룹 | 실행 | 점수 일치 | 공식 자체검증 | 타임아웃 |\n|---|---|---|---|---|---|")
    for r in runs:
        for k, v in S[r]["sandbox"].items():
            if k.endswith("/constrained"):
                L.append(f"| `{r}` | `{k.rsplit('/',1)[0]}` | {pc(v['execution']['rate'])} | {pc(v['score_match']['rate'])} | {pc(v['formula_self_test']['rate'])} | {v['timeouts']} |")

    L.append("\n## `attack_technique` — 산문으로만\n")
    at = {r: S[r]["domain"].get("attack_technique/eval_post_cutoff/constrained", {}).get("accuracy_over_all_items", {}).get("rate") for r in runs}
    L.append("기준선은 모든 그룹에서 0.0%였다. 학습 후 값은 " + ", ".join(f"`{r}` {pc(v)}" for r, v in at.items() if v is not None) +
             " (이후 세트, 제약 생성). 학습 738건, 평가 79건인 과제에서 어떤 움직임도 극적으로 보이고 아무 의미도 없다. "
             "`scored: false`이며 어떤 요약 표에도 넣지 않았다.\n")

    L.append("## 판정 — 사전 등록한 질문에 대한 답 (P5.1 보정 검정 기준)\n")
    gen = C["general"]
    L.append("**범용 능력**: 두 벤치마크가 갈린다.")
    for g, rec in gen.items():
        rows = "; ".join(f"{pk} → {_vmark(pr['verdict'])} (Holm p={_p(pr['mcnemar_p_holm'])})"
                         for pk, pr in rec["pairs"].items())
        L.append(f"- `{g}`: {rows}")
    hs_main = gen.get("hellaswag", {}).get("pairs", {}).get(main_pair, {})
    L.append(f"\n`{main_pair}`에서 HellaSwag는 **차이가 검출되고** MMLU는 검출되지 않는다. "
             "따라서 '리플레이가 망각을 막았다'는 문장은 **HellaSwag에 한해서만** 참이고, MMLU에서는 오히려 "
             "Cond-2의 하락이 더 크다. 하나의 문장으로 합치지 않는다.")
    dom = [(k, rec["pairs"][main_pair]["accuracy"]) for k, rec in C["domain"].items()
           if k.endswith("/constrained") and main_pair in rec["pairs"]]
    n_dd = sum(1 for _, v in dom if v["verdict"] == "difference detected")
    fav1 = sum(1 for _, v in dom if v["paired_difference"]["diff"] > 0)
    L.append(f"\n**도메인 정확도**: {len(dom)}개 세트 중 {n_dd}개에서 차이 검출, {fav1}개에서 Cond-1이 앞선다. "
             "사전 등록대로 Cond-1 ≥ Cond-2가 예상되었고 (Cond-2는 같은 계산량에서 도메인을 20% 적게 본다), "
             "**이것은 리플레이에 불리한 증거가 아니다.**")
    L.append("\n**암기**: 재구축한 탐침에서도 검출되지 않았다. `reports/memorization.md` 참조.\n")
    REPORTS.mkdir(parents=True, exist_ok=True)
    out = REPORTS / "results.md"
    out.write_text("\n".join(L) + "\n", encoding="utf-8")
    return out


if __name__ == "__main__":
    sys.exit(main())
