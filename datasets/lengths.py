"""Token-length distribution and packing yield at 4096 -- this is what turns
the P0 step-cost measurement into a P5 schedule.

The 129.5 s/step figure was measured at 16 x 4096 = 65,536 tokens per optimizer
step with synthetic full-length sequences. Real examples are far shorter, so the
number of examples one step actually trains is the packing yield, not 16.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from datasets import temporal  # noqa: E402
from datasets.common import OUT, REPO, iter_jsonl  # noqa: E402

TASKS = ("cve_to_cwe", "cvss_vector", "attack_technique", "structured_extract", "replay")
SPLITS = (temporal.TRAIN, temporal.EVAL_POST, temporal.EVAL_PRE)
SEQ = 4096
THRESHOLDS = (512, 1024, 2048, 4096)


def pct(v, q):
    if not v:
        return 0
    v = sorted(v)
    return v[min(len(v) - 1, int(round(q * (len(v) - 1))))]


def greedy_pack(lengths, seq=SEQ):
    """Sequential greedy: append to the open bin while it fits, else open a new one.
    Sequences longer than seq are truncated to seq and counted."""
    bins, cur, truncated = 0, 0, 0
    for L in lengths:
        if L > seq:
            truncated += 1
            L = seq
        if cur + L > seq:
            bins += 1
            cur = L
        else:
            cur += L
    if cur:
        bins += 1
    used = sum(min(L, seq) for L in lengths)
    return {"sequences_4096": bins, "examples_per_sequence": round(len(lengths) / bins, 3) if bins else 0,
            "padding_fraction": round(1 - used / (bins * seq), 4) if bins else 0, "truncated_over_4096": truncated}


def main() -> int:
    gate = json.loads((REPO / "env" / "gate0.json").read_text())
    p0 = gate["summary"]["headline"]
    sec_per_step = p0.get("sec_per_optimizer_step")
    tokens_per_step = 16 * SEQ   # batch 4 x grad-accum 4 x seq 4096, as measured in check 07

    out = {"seq": SEQ, "p0_sec_per_step": sec_per_step, "p0_tokens_per_step": tokens_per_step, "tasks": {}}
    total_train_tokens = 0
    total_train_seqs = 0
    # Condition pools, by file: Cond-1 is the 60k subsample; Cond-2 is its
    # domain subset plus the replay drawn against the same total budget.
    sub = {"cond1": [], "cond2_domain": [], "cond2_replay": []}
    for t in TASKS:
        for sp in SPLITS + ("train_subsample", "train_cond2_domain", "train_cond2"):
            p = OUT / t / f"{sp}.jsonl"
            if not p.exists():
                continue
            pr, tg, tot = [], [], []
            for ex in iter_jsonl(p):
                a, b = ex["n_prompt_tokens"], ex["n_target_tokens"]
                pr.append(a); tg.append(b); tot.append(a + b)
            if not tot:
                continue
            if sp == "train_subsample" and t != "replay":
                sub["cond1"].extend(tot)
            elif sp == "train_cond2_domain":
                sub["cond2_domain"].extend(tot)
            elif sp == "train_cond2" and t == "replay":
                sub["cond2_replay"].extend(tot)
            pack = greedy_pack(tot)
            row = {
                "examples": len(tot),
                "prompt": {"p50": pct(pr, .5), "p90": pct(pr, .9), "p99": pct(pr, .99), "max": max(pr)},
                "target": {"p50": pct(tg, .5), "p90": pct(tg, .9), "p99": pct(tg, .99), "max": max(tg)},
                "total": {"p50": pct(tot, .5), "p90": pct(tot, .9), "p99": pct(tot, .99), "max": max(tot),
                          "sum": sum(tot)},
                "fraction_over": {str(th): round(sum(1 for x in tot if x > th) / len(tot), 5) for th in THRESHOLDS},
                "packing": pack,
            }
            out["tasks"][f"{t}/{sp}"] = row
            if sp == temporal.TRAIN:
                total_train_tokens += sum(tot)
                total_train_seqs += pack["sequences_4096"]

    # Pre-registered ablation at EQUAL COMPUTE. Cond-1 = T tokens of domain.
    # Cond-2 = 0.8T domain (a subset of Cond-1) + 0.2T replay. Equal tokens do
    # not by themselves give equal steps, because packing padding differs, so
    # the schedule fixes one step count for both conditions and reports what
    # each condition leaves unused at that count.
    def sched(lengths, label):
        pk = greedy_pack(lengths)
        return {"label": label, "examples": len(lengths), "tokens": sum(lengths),
                "sequences_4096": pk["sequences_4096"], "examples_per_sequence": pk["examples_per_sequence"],
                "padding_fraction": pk["padding_fraction"],
                "optimizer_steps_available": round(pk["sequences_4096"] / 16, 2)}
    c1 = sched(sub["cond1"], "Cond-1: domain only, T tokens")
    c2 = sched(sub["cond2_domain"] + sub["cond2_replay"], "Cond-2: 0.8T domain (subset of Cond-1) + 0.2T replay")
    shared_steps = min(c1["sequences_4096"], c2["sequences_4096"]) // 16
    for c in (c1, c2):
        c["optimizer_steps_per_epoch"] = shared_steps
        c["sequences_consumed"] = shared_steps * 16
        c["sequences_left_over"] = c["sequences_4096"] - shared_steps * 16
        c["hours_per_epoch_at_p0_step_cost"] = round(shared_steps * sec_per_step / 3600, 2) if sec_per_step else None
    assert c1["optimizer_steps_per_epoch"] == c2["optimizer_steps_per_epoch"], "conditions do not run equal steps"
    dt, rt = sum(sub["cond2_domain"]), sum(sub["cond2_replay"])
    out["equal_budget_schedule"] = {
        "cond1": c1, "cond2": c2,
        "shared_optimizer_steps_per_epoch": shared_steps,
        "steps_match": c1["optimizer_steps_per_epoch"] == c2["optimizer_steps_per_epoch"],
        "token_budget_T": c1["tokens"],
        "cond2_total_tokens": c2["tokens"],
        "token_gap_vs_T": c1["tokens"] - c2["tokens"],
        "token_gap_fraction": round((c1["tokens"] - c2["tokens"]) / c1["tokens"], 6) if c1["tokens"] else 0.0,
        "replay_fraction_of_cond2_tokens": round(rt / (dt + rt), 4) if (dt or rt) else 0.0,
        "cond1_examples": c1["examples"],
        "cond2_domain_examples": len(sub["cond2_domain"]),
        "cond2_replay_examples": len(sub["cond2_replay"]),
        "cond2_domain_share_of_cond1_examples": round(len(sub["cond2_domain"]) / c1["examples"], 4) if c1["examples"] else 0.0,
        "note": ("Both conditions run the same number of optimizer steps at the same step cost, so any "
                 "difference between them is the data mix, not the amount of training. The condition with "
                 "the larger packed-sequence count leaves sequences_left_over unused at that step count."),
    }
    # Full set, for the optional run after the ablation.
    steps_per_epoch = total_train_seqs / 16 if total_train_seqs else 0
    out["schedule"] = {
        "train_tokens_all_tasks_plus_replay": total_train_tokens,
        "train_sequences_4096_after_packing": total_train_seqs,
        "sequences_per_optimizer_step": 16,
        "optimizer_steps_per_epoch": round(steps_per_epoch, 1),
        "hours_per_epoch_at_p0_step_cost": round(steps_per_epoch * sec_per_step / 3600, 2) if sec_per_step else None,
        "note": ("Derived from the P0 measurement (129.5 s per 65,536-token step) and the packing yield above. "
                 "Padding fraction is already inside the sequence count, so this is wall time for the real "
                 "corpus, not for 4096-token synthetic rows."),
    }
    (OUT / "lengths.json").write_text(json.dumps(out, indent=2) + "\n")
    print(json.dumps(out["equal_budget_schedule"], indent=1))
    print(json.dumps(out["schedule"], indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main())
