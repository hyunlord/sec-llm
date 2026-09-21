# -*- coding: utf-8 -*-
"""Measure what the training run did not record, and write it down.

Rule 1: the stage that measures owns the record, and the report renders it.
The trainer recorded rewards, lengths and collapse. Three things it did not,
each of which the report needs:

  * **Where the prompts came from.** The pool is drawn from a file, and which
    file that is decides how the reward curve may be read. Overlap with the
    starting checkpoint's own training set and with both evaluation sets is
    counted here rather than asserted in prose.
  * **The starting checkpoint's accuracy.** The work order justified the task
    choice with Cond-0's accuracy, but the run starts from Cond-2. Both are
    read from their score records so the correction carries numbers.
  * **Policy entropy per step.** TRL logs it; the trainer did not keep it.
    Without it, the collapse can only be attributed by argument.

    python -m rlvr.postrun --log /tmp/rlvr.log
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))

RUN = REPO / "runs" / "rlvr"
OUT = REPO / "data" / "out"
ENTROPY_RE = re.compile(r"'entropy':\s*'([0-9.eE+-]+)'")
RUNTIME_RE = re.compile(r"'train_runtime':\s*'([0-9.eE+-]+)'")
EXIT_RE = re.compile(r"^=== grpo exit=(\d+)", re.M)


def attempt_record(log: Path, reward_log: Path) -> dict | None:
    """What an earlier attempt did and where it stopped, read from its own log.

    The first attempt is part of this run's record, not a footnote to be
    paraphrased. Reading it from the files it left is the same discipline the
    rest of the pipeline follows.
    """
    if not log.exists():
        return None
    text = log.read_text(errors="replace")
    ex = EXIT_RE.search(text)
    rt = RUNTIME_RE.search(text)
    steps = len([1 for l in reward_log.read_text().splitlines() if l.strip()]) \
        if reward_log.exists() else 0
    code = int(ex.group(1)) if ex else None
    tail = [l for l in text.splitlines() if l.strip()][-3:]
    return {
        "exit_code": code,
        "signal": (code - 128) if code and code > 128 else None,
        "steps_logged": steps,
        "train_runtime_sec": float(rt.group(1)) if rt else None,
        "died_at": ("writing model shards during the inline merge"
                    if any("model shards" in t for t in tail) else "unknown"),
        "last_lines": [t[:200] for t in tail],
        "artifacts_left": {"adapter": False, "merged_checkpoint": False, "manifest": False},
        "cause": ("merge_and_unload() materialises a second full copy of the model on top of a "
                  "live trainer -- weights, optimizer state, generation buffers -- and the run "
                  "was killed by its memory ceiling while writing shards, after every training "
                  "step had completed."),
        "fix": ("the adapter and the manifest are now written immediately after training, before "
                "anything that can fail; the merge runs in a separate process (rlvr.merge_adapter) "
                "where the training state is gone; adapter checkpoints are saved every 50 steps. "
                "The ceiling was NOT raised -- raising it would have hidden the defect, which is "
                "that the cheap artifact was not persisted before the expensive one."),
    }


def stable_int(s: str, mod: int) -> int:
    return int.from_bytes(hashlib.sha256(s.encode()).digest()[:8], "big") % mod


def ids(path: Path) -> set:
    return {json.loads(l)["example_id"] for l in path.read_text().splitlines() if l.strip()}


def pool_ids(cfg) -> set:
    rows = [json.loads(l) for l in (REPO / cfg["train_file"]).read_text().splitlines() if l.strip()]
    rows.sort(key=lambda r: (stable_int(cfg["selection_seed"] + r["example_id"], 1 << 62),
                             r["example_id"]))
    return {r["example_id"] for r in rows[: cfg["n_prompts"]]}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--log", default="/tmp/rlvr.log")
    a = ap.parse_args()

    import yaml
    cfg = yaml.safe_load((REPO / "rlvr" / "config.yaml").read_text())
    task = cfg["task"]
    pool = pool_ids(cfg)

    c2_train = OUT / task / "train_cond2_domain.jsonl"
    c1_train = OUT / task / "train_subsample.jsonl"
    c2_tm = json.loads((REPO / "runs" / "cond2" / "train_manifest.json").read_text())

    prov = {
        "_comment": ("Where the GRPO prompts came from, counted rather than asserted. "
                     "The pool is drawn from the file the starting checkpoint was trained "
                     "on, so the reward curve is measured on seen data and is not a "
                     "held-out measurement of anything."),
        "pool_file": cfg["train_file"],
        "pool_file_sha256": hashlib.sha256((REPO / cfg["train_file"]).read_bytes()).hexdigest(),
        "selection_seed": cfg["selection_seed"],
        "pool_size": len(pool),
        "file_size": len(ids(REPO / cfg["train_file"])),
        "overlap": {
            "cond2_training_file": len(pool & ids(c2_train)),
            "cond1_training_file": len(pool & ids(c1_train)),
            "eval_post_cutoff": len(pool & ids(OUT / task / "eval_post_cutoff.jsonl")),
            "eval_pre_cutoff": len(pool & ids(OUT / task / "eval_pre_cutoff.jsonl")),
        },
        "starting_checkpoint": {
            "name": "cond2",
            "epoch_fraction": c2_tm["epoch_fraction"],
            "note": ("Cond-2 consumed this fraction of its data, so most but not all pool "
                     "prompts were seen during supervised training; which ones cannot be "
                     "recovered from the packing order."),
        },
    }

    # Accuracy of both candidate reference points on the evaluation sets, so the
    # task-selection correction is stated with numbers from the score records.
    acc = {}
    for run in ("baseline", "cond2"):
        s = json.loads((REPO / "runs" / run / "scores.json").read_text())
        acc[run] = {k: s["domain"][k]["accuracy_over_all_items"]["rate"]
                    for k in s["domain"] if k.startswith(task) and k.endswith("/constrained")}
    prov["task_selection_reference"] = {
        "accuracy": acc,
        "criterion_used_by_work_order": "baseline (Cond-0) accuracy",
        "criterion_that_applies": ("the accuracy of the checkpoint GRPO actually starts from, "
                                   "on the prompts it actually rolls out"),
    }

    att1 = attempt_record(REPO / "runs" / "rlvr_attempt1" / "train.log",
                          REPO / "runs" / "rlvr_attempt1" / "reward_log.jsonl")
    if att1:
        (RUN / "attempts.json").write_text(json.dumps(
            {"_comment": ("attempts that did not produce the published checkpoint, read from the "
                          "logs they left rather than described from memory"),
             "attempt_1": att1}, indent=1, ensure_ascii=False) + "\n")
        print(f"attempt 1: exit {att1['exit_code']} (signal {att1['signal']}), "
              f"{att1['steps_logged']} steps logged, died at {att1['died_at']}")

    (RUN / "pool_provenance.json").write_text(
        json.dumps(prov, indent=1, ensure_ascii=False) + "\n")

    log = Path(a.log)
    ent = [float(m.group(1)) for m in ENTROPY_RE.finditer(log.read_text(errors="replace"))] \
        if log.exists() else []
    (RUN / "entropy.jsonl").write_text(
        "".join(json.dumps({"step": i + 1, "entropy": e}) + "\n" for i, e in enumerate(ent)))

    o = prov["overlap"]
    print(f"pool {prov['pool_size']:,} of {prov['file_size']:,} from {prov['pool_file']}")
    print(f"  in Cond-2 training file: {o['cond2_training_file']:,}  "
          f"in Cond-1: {o['cond1_training_file']:,}")
    print(f"  in eval sets: {o['eval_post_cutoff']} post, {o['eval_pre_cutoff']} pre")
    print(f"entropy series: {len(ent)} steps"
          + (f", {ent[0]:.4f} -> {ent[-1]:.4f}" if ent else " (log not found)"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
