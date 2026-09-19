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
    for t in TASKS:
        for sp in SPLITS:
            p = OUT / t / f"{sp}.jsonl"
            if not p.exists():
                continue
            pr, tg, tot = [], [], []
            for ex in iter_jsonl(p):
                a, b = ex["n_prompt_tokens"], ex["n_target_tokens"]
                pr.append(a); tg.append(b); tot.append(a + b)
            if not tot:
                continue
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

    # P5 schedule from measured numbers: one optimizer step = 16 packed sequences.
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
    print(json.dumps(out["schedule"], indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main())
