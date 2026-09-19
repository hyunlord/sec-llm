"""Materialize the four tasks. P2 marked; this is where marks become material.

Every example is built from fields the source already supplied. No target is
inferred, no instruction is paraphrased, and no CVE appears in more than one
split -- the split is assigned once per CVE and checked, not assumed.
"""

from __future__ import annotations

import hashlib
import json
import sys
import time
from collections import Counter, defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import jsonschema  # noqa: E402

from datasets import contamination, cwe_policy, replay, temporal  # noqa: E402
from datasets.common import (  # noqa: E402
    ATTACK_TABLE, CVE_TABLE, OUT, SCHEMAS, ensure_dirs, iter_jsonl, stable_int, write_jsonl,
)
from datasets.templates import render  # noqa: E402
from datasets.tokenize_qwen import n_tokens  # noqa: E402

TASKS = ("cve_to_cwe", "cvss_vector", "attack_technique", "structured_extract")
SPLITS_OUT = (temporal.TRAIN, temporal.EVAL_POST, temporal.EVAL_PRE)
MAX_VERSIONS = 16
MIN_ATTACK_DESC_CHARS = 40
SUBSAMPLE_N = 60_000
SUBSAMPLE_SEED = "sec-llm-p5-subsample-v1"

_validators = {t: jsonschema.Draft202012Validator(json.loads((SCHEMAS / f"{t}.json").read_text())) for t in TASKS}


def make_example(task, entity_id, split, input_text, target, meta):
    eid = f"{task}:{entity_id}"
    tpl_id, prompt = render(task, eid, input_text)
    errors = sorted(_validators[task].iter_errors(target), key=str)
    if errors:
        raise ValueError(f"{eid}: target fails schema: {errors[0].message}")
    target_json = json.dumps(target, ensure_ascii=False, sort_keys=True)
    return {
        "example_id": eid,
        "task": task,
        "split": split,
        "entity_id": entity_id,
        "template_id": tpl_id,
        "prompt": prompt,
        "input": input_text,
        "target": target,
        "target_json": target_json,
        "n_prompt_tokens": n_tokens(prompt),
        "n_target_tokens": n_tokens(target_json),
        "meta": meta,
    }


def _ids_sha(ids) -> str:
    """Stable digest of an example-id set: sha256 over the sorted ids, newline
    joined. Two such digests are what the Cond-2 subset proof compares."""
    return hashlib.sha256("\n".join(sorted(ids)).encode("utf-8")).hexdigest()


def _sweep_stale(written: set[str]) -> list[str]:
    """Delete .jsonl files this build did not write. Without this a file from an
    earlier design (replay/train_subsample.jsonl, superseded by the equal-budget
    conditions) survives on disk, gets globbed into the manifest, and the
    manifest stops describing what the build produced."""
    gone = []
    for t in TASKS + ("replay",):
        d = OUT / t
        if not d.exists():
            continue
        for p in sorted(d.glob("*.jsonl")):
            if f"{t}/{p.stem}" not in written:
                p.unlink()
                gone.append(f"{t}/{p.name}")
    return gone


def main() -> int:
    ensure_dirs()
    t0 = time.time()
    cve_rows = list(iter_jsonl(CVE_TABLE))
    attack_rows = list(iter_jsonl(ATTACK_TABLE))
    split = temporal.assign_splits(cve_rows)
    asplit = temporal.assign_attack_splits(attack_rows)

    # Split-integrity check, in code. One label per CVE and the two eval sets
    # are disjoint by construction; both facts are verified rather than trusted.
    ev_post = {c for c, s in split.items() if s == temporal.EVAL_POST}
    ev_pre = {c for c, s in split.items() if s == temporal.EVAL_PRE}
    assert not (ev_post & ev_pre), "a CVE is in both temporal eval sets"
    assert len(split) == len(cve_rows) == len({r["cve_id"] for r in cve_rows})
    split_counts = Counter(split.values())
    write_jsonl(OUT / "split_map.jsonl", ({"cve_id": c, "split": s} for c, s in sorted(split.items())))

    resolved = {r["cve_id"]: cwe_policy.resolve(r) for r in cve_rows}
    by_id = {r["cve_id"]: r for r in cve_rows}

    # CWE guard: cluster -> representative, for re-admitting dropped near-dup
    # members whose label differs from the representative's. (P2.1 never
    # landed; this is the minimum P3 requires, kept out of process/.)
    rep_of: dict[str, str] = {}
    for r in cve_rows:
        if r.get("dedup_role") == "representative" and r.get("dedup_cluster_id"):
            rep_of[r["dedup_cluster_id"]] = r["cve_id"]

    examples: dict[str, dict[str, list]] = {t: defaultdict(list) for t in TASKS}
    stats: dict[str, dict] = {t: {"excluded_by_dedup": Counter(), "excluded_by_filter": Counter(),
                                  "by_split": Counter(), "by_template": Counter()} for t in TASKS}
    contested_rows = []
    cwe_buckets = Counter()
    cwe_source_by_split = defaultdict(Counter)
    guard = Counter()
    contested_structure = {"pairs": Counter(), "cnas": Counter(), "relation": Counter()}
    cvss_missing = Counter()
    se_excl = Counter()

    for r in cve_rows:
        cid = r["cve_id"]
        res = resolved[cid]
        sp = split[cid]
        cwe_buckets[res["bucket"]] += 1
        if res["bucket"] == "rejected":
            continue

        # ---- dedup gate (all CVE tasks) ----
        kept = bool(r["dedup_keep"])
        readmit_cwe = False
        if not kept:
            stage = r["dedup_stage"]
            for t in ("cve_to_cwe", "cvss_vector", "structured_extract"):
                stats[t]["excluded_by_dedup"][stage] += 1
            # Guard applies to the CWE task only, and only into training.
            if (stage == "near" and res["cwe_id"]
                    and temporal.period(r["date_published"], r["year"]) in ("pre_cutoff_other", "pre_eval_window")):
                rep = rep_of.get(r["dedup_cluster_id"])
                rep_lab = resolved.get(rep, {}).get("cwe_id") if rep else None
                rep_split = split.get(rep)
                if rep_lab and rep_lab != res["cwe_id"]:
                    if rep_split in (temporal.EVAL_POST, temporal.EVAL_PRE):
                        guard["not_readmitted_rep_in_eval"] += 1
                    else:
                        readmit_cwe = True
                        guard["readmitted_to_train"] += 1
                elif rep_lab == res["cwe_id"]:
                    guard["dropped_same_label"] += 1
                else:
                    guard["dropped_rep_unlabelled"] += 1

        # ---- cve_to_cwe ----
        if res["bucket"] == "contested":
            contested_structure["relation"][res["relation"]] += 1
            contested_structure["cnas"][r["assigner"] or "?"] += 1
            c, n = r["cna_cwes"], r["nvd_cwes"]
            if len(c) == 1 and len(n) == 1:
                contested_structure["pairs"][f"{c[0]}->{n[0]}"] += 1
            if kept:
                contested_rows.append({"cve_id": cid, "split_would_be": sp, "cna_cwes": c, "nvd_cwes": n,
                                       "relation": res["relation"], "assigner": r["assigner"],
                                       "input": r["description"]})
        elif res["cwe_id"] and (kept or readmit_cwe):
            tsp = temporal.TRAIN if readmit_cwe else sp
            if tsp in SPLITS_OUT:
                if not r["description"]:
                    stats["cve_to_cwe"]["excluded_by_filter"]["empty_description"] += 1
                else:
                    meta = {"cwe_source": res["cwe_source"], "year": r["year"], "assigner": r["assigner"],
                            "dedup_stage": r["dedup_stage"], "guard_readmitted": readmit_cwe}
                    ex = make_example("cve_to_cwe", cid, tsp, r["description"], {"cwe_id": res["cwe_id"]}, meta)
                    examples["cve_to_cwe"][tsp].append(ex)
                    cwe_source_by_split[tsp][res["cwe_source"]] += 1
            else:
                stats["cve_to_cwe"]["excluded_by_filter"][tsp] += 1
        elif kept:
            stats["cve_to_cwe"]["excluded_by_filter"][f"bucket_{res['bucket']}"] += 1

        if not kept:
            continue

        # ---- cvss_vector ----
        cv = r.get("cvss31")
        if not cv:
            pres = tuple(r.get("cvss_versions_present") or [])
            cvss_missing["+".join(p.replace("cvssMetric", "") for p in pres) or "none"] += 1
            stats["cvss_vector"]["excluded_by_filter"]["no_v31_metric"] += 1
        elif sp in SPLITS_OUT:
            target = {k: cv[k] for k in ("attackVector", "attackComplexity", "privilegesRequired", "userInteraction",
                                         "scope", "confidentialityImpact", "integrityImpact", "availabilityImpact",
                                         "baseScore", "vectorString")}
            if any(v is None for v in target.values()) or not r["description"]:
                stats["cvss_vector"]["excluded_by_filter"]["incomplete_metric_or_empty_desc"] += 1
            else:
                meta = {"year": r["year"], "assigner": r["assigner"], "dedup_stage": r["dedup_stage"],
                        "baseSeverity": cv.get("baseSeverity")}
                examples["cvss_vector"][sp].append(make_example("cvss_vector", cid, sp, r["description"], target, meta))
        else:
            stats["cvss_vector"]["excluded_by_filter"][sp] += 1

        # ---- structured_extract ----
        aff = [a for a in r["affected"] if a["product"] and a["product"].strip().lower() != "n/a"]
        if not aff:
            se_excl["no_affected_product"] += 1
        elif len(aff) > 1:
            se_excl["multiple_affected_products"] += 1
        else:
            a = aff[0]
            vers = [v for v in a["versions"] if v.strip() and v.strip().lower() != "n/a"]
            vendor = (a["vendor"] or "").strip()
            if not vendor or vendor.lower() == "n/a":
                se_excl["vendor_na"] += 1
            elif not vers:
                se_excl["no_affected_versions"] += 1
            elif len(vers) > MAX_VERSIONS:
                se_excl[f"more_than_{MAX_VERSIONS}_versions"] += 1
            elif not r["description"]:
                se_excl["empty_description"] += 1
            elif sp in SPLITS_OUT:
                target = {"vendor": vendor, "product": a["product"].strip(), "versions": vers,
                          "impact": (r["impacts"][0] if r["impacts"] else None)}
                meta = {"year": r["year"], "assigner": r["assigner"], "dedup_stage": r["dedup_stage"],
                        "impact_present": bool(r["impacts"]), "n_versions": len(vers)}
                examples["structured_extract"][sp].append(
                    make_example("structured_extract", cid, sp, r["description"], target, meta))
            else:
                stats["structured_extract"]["excluded_by_filter"][sp] += 1
    for k, v in se_excl.items():
        stats["structured_extract"]["excluded_by_filter"][k] = v
    stats["cvss_vector"]["missing_v31_by_versions_present"] = dict(cvss_missing)

    # ---- attack_technique ----
    for a in attack_rows:
        sp = asplit[a["technique_id"]]
        if not a["dedup_keep"]:
            stats["attack_technique"]["excluded_by_dedup"]["near_or_exact"] += 1
            continue
        if len(a["description"]) < MIN_ATTACK_DESC_CHARS:
            stats["attack_technique"]["excluded_by_filter"]["description_too_short"] += 1
            continue
        if sp not in SPLITS_OUT:
            stats["attack_technique"]["excluded_by_filter"][sp] += 1
            continue
        meta = {"name": a["name"], "is_subtechnique": a["is_subtechnique"], "created": a["created"],
                "domains": a["domains"], "tactics": a["tactics"], "leak_removed": a["leak_removed"]}
        examples["attack_technique"][sp].append(
            make_example("attack_technique", a["technique_id"], sp, a["description"], {"technique_id": a["technique_id"]}, meta))

    # ---- replay, budgeted against the FULL domain training set ----
    domain_train_tokens = sum(e["n_prompt_tokens"] + e["n_target_tokens"]
                              for t in TASKS for e in examples[t][temporal.TRAIN])
    pairs, rstats = replay.load_pairs()
    pairs, scan = replay.scan_and_redact(pairs)
    chosen, budget = replay.sample_to_budget(pairs, n_tokens, domain_train_tokens)

    def replay_row(p):
        return {"example_id": p["replay_id"], "task": "replay", "split": temporal.TRAIN, "entity_id": p["replay_id"],
                "template_id": None, "prompt": p["prompt"], "input": p["prompt"], "target": None,
                "target_json": p["response"], "n_prompt_tokens": n_tokens(p["prompt"]),
                "n_target_tokens": n_tokens(p["response"]), "meta": {"lang": p["lang"], "rank": p.get("rank")}}
    rrows = [replay_row(p) for p in chosen]

    # ---- contamination screening: build.py OWNS removal and its record ----
    # (docs/engineering-rules.md rule 1). Everything the model will train on is
    # the training side: every task's inputs and targets, and replay prompts and
    # responses. Each eval entity is screened once and the verdict applies to
    # every task it appears in, so the same CVE cannot be kept in one task and
    # removed from another.
    train_texts = []
    for t in TASKS:
        for e in examples[t][temporal.TRAIN]:
            train_texts.append((f"{t}:{e['entity_id']}:in", e["input"]))
            train_texts.append((f"{t}:{e['entity_id']}:tg", e["target_json"]))
    for r in rrows:
        train_texts.append((f"replay:{r['entity_id']}:in", r["input"]))
        train_texts.append((f"replay:{r['entity_id']}:tg", r["target_json"]))
    eval_by_entity = {}
    for t in TASKS:
        for sp in (temporal.EVAL_POST, temporal.EVAL_PRE):
            for e in examples[t][sp]:
                eval_by_entity.setdefault(e["entity_id"], e["input"])
    print(f"  screening {len(eval_by_entity):,} eval entities against {len(train_texts):,} training texts", flush=True)
    verdicts, idx_stats = contamination.screen(eval_by_entity, train_texts)

    removal_record = []
    contam_sets = {}
    cna_dist = {}
    cross = {}
    cov_all, jac_all = [], []
    recon = Counter()
    for t in TASKS:
        train_cna = Counter(e["meta"].get("assigner") or "?" for e in examples[t][temporal.TRAIN]) if t != "attack_technique" else None
        for sp in (temporal.EVAL_POST, temporal.EVAL_PRE):
            rows = examples[t][sp]
            keep, rem = [], []
            n_old = n_p31 = n_restored = 0
            for e in rows:
                v = verdicts[e["entity_id"]]
                cov_all.append(v["coverage_13"]["fraction"]); jac_all.append(v["near_match"]["jaccard"])
                if v["diag_any_13gram"]:
                    n_old += 1
                if v["removed"] or v["diag_p31_coverage"]:
                    n_p31 += 1                       # P3.1 would have removed this
                if v["removed"]:
                    rem.append(e)
                    removal_record.append({
                        "task": t, "split": sp, "example_id": e["example_id"], "entity_id": e["entity_id"],
                        "assigner": e["meta"].get("assigner"), "criteria": v["criteria"],
                        "near_match": v["near_match"], "coverage_13": v["coverage_13"],
                        "coverage_8_fraction": v["coverage_8_fraction"], "diag_any_13gram": v["diag_any_13gram"],
                        "diag_p31_coverage_also_fired": v["diag_p31_coverage"],
                    })
                else:
                    if v["diag_p31_coverage"]:
                        n_restored += 1              # P3.1 removed it; P3.2 keeps it
                    # Coverage travels with the item. P4 stratifies on this.
                    e["train_ngram_coverage"] = v["coverage_13"]["fraction"]
                    keep.append(e)
            # Quartile boundaries are read off the delivered set, then stamped
            # on each item so P4 needs no recomputation to stratify.
            qb = contamination.quartiles([e["train_ngram_coverage"] for e in keep])
            qc = Counter()
            for e in keep:
                q = contamination.quartile_of(e["train_ngram_coverage"], qb)
                e["train_ngram_coverage_quartile"] = q
                qc[f"q{q}"] += 1
            examples[t][sp] = keep
            key = f"{t}/{sp}"
            recon["p31_would_remove"] += n_p31; recon["p32_removed"] += len(rem); recon["restored"] += n_restored
            contam_sets[key] = {
                "before": len(rows), "after": len(keep), "removed": len(rem),
                "removed_fraction": round(len(rem) / len(rows), 4) if rows else 0.0,
                "removed_by_near_duplicate": len(rem),
                "restored_p31_coverage_only": n_restored,
                "diag_p31_criterion_would_remove": n_p31,
                "diag_old_criterion_would_remove": n_old,
                "diag_old_criterion_fraction": round(n_old / len(rows), 4) if rows else 0.0,
                "coverage_quartiles": qb, "coverage_quartile_counts": dict(qc),
                "coverage_zero": sum(1 for e in keep if e["train_ngram_coverage"] == 0.0),
            }
            if train_cna is not None:
                def cna(items):
                    return Counter(e["meta"].get("assigner") or "?" for e in items)
                before = cna(rows)
                after_old = cna([e for e in rows if not verdicts[e["entity_id"]]["diag_any_13gram"]])
                after_p31 = cna([e for e in rows if not (verdicts[e["entity_id"]]["removed"]
                                                         or verdicts[e["entity_id"]]["diag_p31_coverage"])])
                after_new = cna(keep)
                cna_dist[key] = {
                    "tvd_before": contamination.tvd(before, train_cna),
                    "tvd_after_old": contamination.tvd(after_old, train_cna),
                    "tvd_after_p31": contamination.tvd(after_p31, train_cna),
                    "tvd_after_new": contamination.tvd(after_new, train_cna),
                    "before_top": before.most_common(10), "after_old_top": after_old.most_common(10),
                    "after_p31_top": after_p31.most_common(10),
                    "after_new_top": after_new.most_common(10), "train_top": train_cna.most_common(10),
                }
        post = {e["entity_id"] for e in examples[t][temporal.EVAL_POST]}
        pre = {e["entity_id"] for e in examples[t][temporal.EVAL_PRE]}
        cross[t] = len(post & pre)
        assert not (post & pre), f"{t}: entity in both temporal eval sets"
    edges = [0.0, 0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0]
    # Reconciliation against the P3.1 record, computed not asserted.
    assert recon["p31_would_remove"] == recon["p32_removed"] + recon["restored"], "reconciliation does not close"
    contam = {
        "index": idx_stats, "eval_sets": contam_sets, "total_removed": len(removal_record),
        "total_diag_old_criterion": sum(v["diag_old_criterion_would_remove"] for v in contam_sets.values()),
        "reconciliation_with_p31": {
            "p31_removed_total": recon["p31_would_remove"],
            "p32_removed_total": recon["p32_removed"],
            "restored_coverage_only": recon["restored"],
            "identity": "p31_removed_total = p32_removed_total + restored_coverage_only (checked in build.py)",
            "note": ("P3.1 applied near-duplicate OR coverage>0.5 and removed the union. P3.2 applies "
                     "near-duplicate alone; every item P3.1 removed on coverage alone is back in the set, "
                     "carrying its coverage value as a field."),
        },
        # The leakage finding itself, recorded once here so CARD.md and
        # contamination.md render it instead of recomputing it (rule 1).
        "removed_near_jaccard": contamination.quartiles([r["near_match"]["jaccard"] for r in removal_record]),
        "removed_per_eval_set": {f"{r['task']}/{r['split']}": 0 for r in removal_record},
        "coverage_histogram": contamination.hist(cov_all, edges),
        "near_jaccard_histogram": contamination.hist(jac_all, edges),
        "cna_distribution": cna_dist, "cross_eval": cross,
        "policy": "applied: near_duplicate (Jaccard >= threshold, P2 MinHash), and nothing else. "
                  "measured, NOT applied: 13-gram coverage ratio (attached per item, quartiles per set). "
                  "diagnostic only, NOT applied: any single shared 13-gram; the superseded P3.1 coverage>0.5 rule",
    }
    for r in removal_record:
        contam["removed_per_eval_set"][f"{r['task']}/{r['split']}"] += 1
    removal_record.sort(key=lambda r: r["example_id"] + "|" + r["split"])

    # ---- write task files (post-removal) ----
    files = {}
    for t in TASKS:
        for sp in SPLITS_OUT:
            rows = sorted(examples[t][sp], key=lambda e: e["example_id"])
            n, sha = write_jsonl(OUT / t / f"{sp}.jsonl", rows)
            files[f"{t}/{sp}"] = {"count": n, "sha256": sha}
            stats[t]["by_split"][sp] = n
            for e in rows:
                stats[t]["by_template"][str(e["template_id"])] += 1
    n, sha = write_jsonl(OUT / "cve_to_cwe" / "contested.jsonl", sorted(contested_rows, key=lambda x: x["cve_id"]))
    files["cve_to_cwe/contested"] = {"count": n, "sha256": sha}
    n, sha = write_jsonl(OUT / "replay" / "train.jsonl", rrows)
    files["replay/train"] = {"count": n, "sha256": sha}

    # ---- pre-registered P5 subsample: 60k domain examples, stratified over the
    # three SCORED tasks, seeded, hashed. Both training conditions use exactly
    # this; Cond-2 adds replay budgeted at 20% of the SUBSAMPLE's tokens.
    scored = [t for t in TASKS if t != "attack_technique"]
    totals = {t: len(examples[t][temporal.TRAIN]) for t in scored}
    grand = sum(totals.values())
    quota = {t: round(SUBSAMPLE_N * totals[t] / grand) for t in scored}
    quota[scored[-1]] += SUBSAMPLE_N - sum(quota.values())   # rounding residue to the last task
    cond1: dict[str, list] = {}
    for t in scored:
        order = sorted(examples[t][temporal.TRAIN],
                       key=lambda e: (stable_int(SUBSAMPLE_SEED + e["example_id"], 1 << 62), e["example_id"]))
        pick = sorted(order[:quota[t]], key=lambda e: e["example_id"])
        cond1[t] = pick
        n, sha = write_jsonl(OUT / t / "train_subsample.jsonl", pick)
        files[f"{t}/train_subsample"] = {"count": n, "sha256": sha}
    tok = lambda e: e["n_prompt_tokens"] + e["n_target_tokens"]   # noqa: E731
    T = sum(tok(e) for t in scored for e in cond1[t])

    # ---- equal token budget across conditions (P3.2 change 2) ----
    # Cond-1 = T tokens, all domain. Cond-2 = (1-f)*T domain + f*T replay, so
    # both conditions see the same number of tokens and take the same number of
    # optimizer steps. Previously Cond-2 was Cond-1 PLUS replay: 1.25x the
    # tokens and 1.25x the steps, which confounds "replay prevents forgetting"
    # with "trained longer".
    #
    # Cond-2's domain portion is a prefix of the SAME stable-hash order over the
    # Cond-1 pool -- drawn from Cond-1's members, never from the full training
    # set -- so the subset relation holds by construction and is checked below.
    f = replay.REPLAY_FRACTION_OF_TOTAL
    pool = sorted((e for t in scored for e in cond1[t]),
                  key=lambda e: (stable_int(SUBSAMPLE_SEED + e["example_id"], 1 << 62), e["example_id"]))
    target_domain = int(T * (1 - f))
    cond2_pick, c2_domain_tokens = [], 0
    for e in pool:
        n_ = tok(e)
        if c2_domain_tokens + n_ > target_domain and cond2_pick:
            break
        cond2_pick.append(e)
        c2_domain_tokens += n_
    c2_by_task = {t: sorted((e for e in cond2_pick if e["task"] == t), key=lambda e: e["example_id"])
                  for t in scored}
    for t in scored:
        n, sha = write_jsonl(OUT / t / "train_cond2_domain.jsonl", c2_by_task[t])
        files[f"{t}/train_cond2_domain"] = {"count": n, "sha256": sha}
    # Replay fills exactly what the domain portion left of T, so Cond-2's total
    # is T and not 1.25*T.
    c2_replay, c2_rbudget = replay.sample_to_budget(pairs, n_tokens, c2_domain_tokens,
                                                    budget=T - c2_domain_tokens)
    n, sha = write_jsonl(OUT / "replay" / "train_cond2.jsonl", [replay_row(p) for p in c2_replay])
    files["replay/train_cond2"] = {"count": n, "sha256": sha}

    ids1 = sorted(e["example_id"] for t in scored for e in cond1[t])
    ids2 = sorted(e["example_id"] for e in cond2_pick)
    assert set(ids2) <= set(ids1), "Cond-2 domain is not a subset of Cond-1"
    inter = sorted(set(ids1) & set(ids2))
    h1, h2, hi = (_ids_sha(ids1), _ids_sha(ids2), _ids_sha(inter))
    assert h2 == hi, "subset proof failed: cond2 ids != cond1 ∩ cond2"
    c2_total = c2_domain_tokens + c2_rbudget["replay_tokens_used"]
    subsample = {
        "n": SUBSAMPLE_N, "seed": SUBSAMPLE_SEED, "stratified_over": scored, "quota": quota,
        "source_totals": totals, "domain_tokens": T, "replay": c2_rbudget,
        "conditions": {
            "design": ("equal total token budget T. Cond-1: T domain. Cond-2: (1-f)T domain drawn from "
                       "Cond-1 by the same seed and order, plus fT replay. Both run the same number of "
                       "optimizer steps (see lengths.equal_budget_schedule)."),
            "budget_T_tokens": T,
            "replay_fraction_target": f,
            "cond1": {"label": "Cond-1: domain only, T tokens", "examples": len(ids1), "domain_tokens": T,
                      "replay_tokens": 0, "total_tokens": T, "example_ids_sha256": h1,
                      "files": [f"{t}/train_subsample.jsonl" for t in scored]},
            "cond2": {"label": "Cond-2: 0.8T domain + 0.2T replay", "domain_examples": len(ids2),
                      "domain_tokens": c2_domain_tokens, "replay_pairs": len(c2_replay),
                      "replay_tokens": c2_rbudget["replay_tokens_used"], "total_tokens": c2_total,
                      "replay_fraction_achieved": round(c2_rbudget["replay_tokens_used"] / c2_total, 4),
                      "domain_example_ids_sha256": h2,
                      "files": [f"{t}/train_cond2_domain.jsonl" for t in scored] + ["replay/train_cond2.jsonl"]},
            "budget_residue_tokens": T - c2_total,
            "budget_residue_fraction": round((T - c2_total) / T, 6),
            "subset_proof": {
                "cond2_domain_subset_of_cond1": True,
                "cond1_ids_sha256": h1, "cond2_domain_ids_sha256": h2, "intersection_ids_sha256": hi,
                "method": ("sha256 over sorted example_ids joined by newline. The proof is that the hash of "
                           "Cond-2's ids equals the hash of (Cond-1 ∩ Cond-2); both are recorded so the "
                           "relation is recomputable from the published files."),
                "verify": "python -m datasets.build --verify-subset",
            },
        },
    }

    out = {
        "tasks": {t: {k: (dict(v) if isinstance(v, Counter) else v) for k, v in stats[t].items()} for t in TASKS},
        "scored": {t: (t != "attack_technique") for t in TASKS},
        "not_scored_reason": {"attack_technique": (
            "738 training examples and 72 / 44 evaluation items; confidence intervals exceed +/-10 percentage "
            "points and the task is recall of ~800 fixed items. Kept in the datasets and manifest, reported "
            "descriptively by P4/P5, excluded from any comparison between conditions.")},
        "split_counts_cve": dict(split_counts),
        "split_counts_attack": dict(Counter(asplit.values())),
        "cwe_buckets": dict(cwe_buckets),
        "cwe_source_by_split": {k: dict(v) for k, v in cwe_source_by_split.items()},
        "cwe_guard": dict(guard),
        "cwe_guard_provenance": "interim guard in datasets/build.py; P2.1 not delivered, reconciliation deferred",
        "contested_structure": {"relation": dict(contested_structure["relation"]),
                                "top_pairs": contested_structure["pairs"].most_common(15),
                                "top_cnas": contested_structure["cnas"].most_common(15),
                                "total": sum(contested_structure["relation"].values())},
        "replay": {"parse": rstats, "scan": scan, "budget_full": budget,
                   "lang_counts": dict(Counter(p["lang"] for p in chosen))},
        "subsample": subsample,
        "contamination": contam,
        "removal_record": removal_record,
        "files": files,
        "temporal": {"cutoff": temporal.CUTOFF, "pre_eval_years": list(temporal.PRE_EVAL_YEARS),
                     "eval_sample_per_period": temporal.EVAL_SAMPLE},
    }
    print(json.dumps({t: dict(stats[t]["by_split"]) for t in TASKS}, indent=1))
    print("removed:", {k: v["removed"] for k, v in contam_sets.items()})
    swept = _sweep_stale(set(files))
    if swept:
        print("removed stale files no longer written by this build:", swept)
    out["stale_files_removed"] = swept
    print("replay full:", budget)
    print("subsample:", subsample["quota"])
    co = subsample["conditions"]
    print(f"equal budget T={co['budget_T_tokens']:,}; cond1 {co['cond1']['total_tokens']:,} tok / "
          f"{co['cond1']['examples']:,} ex; cond2 {co['cond2']['total_tokens']:,} tok "
          f"({co['cond2']['domain_examples']:,} domain + {co['cond2']['replay_pairs']:,} replay, "
          f"replay {co['cond2']['replay_fraction_achieved']:.1%}); residue {co['budget_residue_fraction']:.4%}")
    (OUT / "build_stats.json").write_text(json.dumps(out, indent=2, sort_keys=True, ensure_ascii=False) + "\n")
    print(f"build wall {time.time()-t0:.0f}s")
    return 0


def verify_subset() -> int:
    """Recompute the Cond-2 subset relation from the published files, not from
    the manifest's claim about them."""
    scored = [t for t in TASKS if t != "attack_technique"]
    ids1, ids2 = set(), set()
    for t in scored:
        for e in iter_jsonl(OUT / t / "train_subsample.jsonl"):
            ids1.add(e["example_id"])
        for e in iter_jsonl(OUT / t / "train_cond2_domain.jsonl"):
            ids2.add(e["example_id"])
    extra = ids2 - ids1
    inter = ids1 & ids2
    ok = not extra and _ids_sha(ids2) == _ids_sha(inter)
    rec = json.loads((OUT / "build_stats.json").read_text())["subsample"]["conditions"]["subset_proof"]
    match = (rec["cond1_ids_sha256"] == _ids_sha(ids1) and rec["cond2_domain_ids_sha256"] == _ids_sha(ids2))
    print(f"Cond-1 {len(ids1):,} ids  sha256 {_ids_sha(ids1)[:16]}…")
    print(f"Cond-2 {len(ids2):,} ids  sha256 {_ids_sha(ids2)[:16]}…")
    print(f"Cond-2 \\ Cond-1 = {len(extra)} ids (must be 0); sha256(Cond-2) == sha256(Cond-1 ∩ Cond-2): {ok}")
    print(f"digests match the recorded proof in build_stats.json: {match}")
    print("SUBSET VERIFIED" if (ok and match) else "SUBSET CHECK FAILED")
    return 0 if (ok and match) else 1


if __name__ == "__main__":
    if "--verify-subset" in sys.argv:
        sys.exit(verify_subset())
    sys.exit(main())
