"""Materialize the four tasks. P2 marked; this is where marks become material.

Every example is built from fields the source already supplied. No target is
inferred, no instruction is paraphrased, and no CVE appears in more than one
split -- the split is assigned once per CVE and checked, not assumed.
"""

from __future__ import annotations

import json
import sys
import time
from collections import Counter, defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import jsonschema  # noqa: E402

from datasets import cwe_policy, replay, temporal  # noqa: E402
from datasets.common import (  # noqa: E402
    ATTACK_TABLE, CVE_TABLE, OUT, SCHEMAS, ensure_dirs, iter_jsonl, write_jsonl,
)
from datasets.templates import render  # noqa: E402
from datasets.tokenize_qwen import n_tokens  # noqa: E402

TASKS = ("cve_to_cwe", "cvss_vector", "attack_technique", "structured_extract")
SPLITS_OUT = (temporal.TRAIN, temporal.EVAL_POST, temporal.EVAL_PRE)
MAX_VERSIONS = 16
MIN_ATTACK_DESC_CHARS = 40

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

    # ---- write task files ----
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

    # ---- replay: 20% of training tokens ----
    domain_train_tokens = sum(e["n_prompt_tokens"] + e["n_target_tokens"]
                              for t in TASKS for e in examples[t][temporal.TRAIN])
    pairs, rstats = replay.load_pairs()
    pairs, scan = replay.scan_and_redact(pairs)
    chosen, budget = replay.sample_to_budget(pairs, n_tokens, domain_train_tokens)
    rrows = [{"example_id": p["replay_id"], "task": "replay", "split": temporal.TRAIN, "entity_id": p["replay_id"],
              "template_id": None, "prompt": p["prompt"], "input": p["prompt"], "target": None,
              "target_json": p["response"], "n_prompt_tokens": n_tokens(p["prompt"]),
              "n_target_tokens": n_tokens(p["response"]), "meta": {"lang": p["lang"], "rank": p.get("rank")}} for p in chosen]
    n, sha = write_jsonl(OUT / "replay" / "train.jsonl", rrows)
    files["replay/train"] = {"count": n, "sha256": sha}

    out = {
        "tasks": {t: {k: (dict(v) if isinstance(v, Counter) else v) for k, v in stats[t].items()} for t in TASKS},
        "split_counts_cve": dict(split_counts),
        "split_counts_attack": dict(Counter(asplit.values())),
        "cwe_buckets": dict(cwe_buckets),
        "cwe_source_by_split": {k: dict(v) for k, v in cwe_source_by_split.items()},
        "cwe_guard": dict(guard),
        "contested_structure": {"relation": dict(contested_structure["relation"]),
                                "top_pairs": contested_structure["pairs"].most_common(15),
                                "top_cnas": contested_structure["cnas"].most_common(15),
                                "total": sum(contested_structure["relation"].values())},
        "replay": {"parse": rstats, "scan": scan, "budget": budget,
                   "lang_counts": dict(Counter(p["lang"] for p in chosen))},
        "files_pre_contamination": files,
        "temporal": {"cutoff": temporal.CUTOFF, "pre_eval_years": list(temporal.PRE_EVAL_YEARS),
                     "eval_sample_per_period": temporal.EVAL_SAMPLE},
    }
    (OUT / "build_stats.json").write_text(json.dumps(out, indent=2, sort_keys=True, ensure_ascii=False) + "\n")
    print(json.dumps({t: dict(stats[t]["by_split"]) for t in TASKS}, indent=1))
    print("replay:", budget)
    print(f"build wall {time.time()-t0:.0f}s")
    return 0


if __name__ == "__main__":
    sys.exit(main())
