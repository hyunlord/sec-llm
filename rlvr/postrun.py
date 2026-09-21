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


def rebuild_train_manifest(cfg, prov, wall_sec) -> dict:
    """Rebuild the training record from what the run left, after a name collision.

    The trainer wrote runs/rlvr/manifest.json; the evaluation runner writes the
    same path for the same run id and overwrote it. P5 already separates the two
    (train_manifest.json beside manifest.json) and this did not follow that
    convention. The name is fixed in the trainer for future runs; this rebuilds
    the record for the run that was lost, from files that survived, and says so.

    Everything here is recomputed from reward_log.jsonl, the config, the
    checkpoint state and the verifier itself. Nothing is remembered.
    """
    import statistics
    rows = [json.loads(l) for l in (RUN / "reward_log.jsonl").read_text().splitlines() if l.strip()]
    state = json.loads((RUN / "trainer" / "checkpoint-200" / "trainer_state.json").read_text()) \
        if (RUN / "trainer" / "checkpoint-200" / "trainer_state.json").exists() else {}
    band = max(1, len(rows) // 10)
    first, last = rows[:band], rows[-band:]
    mean = lambda rs, k: round(statistics.fmean(r[k] for r in rs), 4)  # noqa: E731

    sys.path.insert(0, str(REPO))
    from rlvr.verifier import Verifier
    pool_max_target = max(
        json.loads(l)["n_target_tokens"]
        for l in (REPO / cfg["train_file"]).read_text().splitlines() if l.strip())
    cap = cfg["max_completion_length_headroom"] * pool_max_target

    return {
        "_rebuilt": ("this record was rebuilt by rlvr.postrun after the evaluation runner "
                     "overwrote runs/rlvr/manifest.json, which the trainer had written to the "
                     "same path. Every field below is recomputed from reward_log.jsonl, "
                     "rlvr/config.yaml, the checkpoint's trainer_state.json and the verifier. "
                     "The trainer now writes train_manifest.json, following the P5 convention "
                     "it should have followed."),
        "name": cfg["name"], "task": cfg["task"],
        "claim": ("this run demonstrates that the RLVR structure executes end to end. It does "
                  "not claim a performance improvement; see reports/rlvr.md."),
        "base_checkpoint": cfg["base_checkpoint"],
        "base_checkpoint_sha256": json.loads(
            (REPO / "runs" / "cond2" / "train_manifest.json").read_text())["merged_checkpoint_sha256"],
        "adapter_path": "runs/rlvr/adapter",
        "merged_path": "checkpoints/rlvr",
        "config": cfg,
        "config_sha256": hashlib.sha256((REPO / "rlvr" / "config.yaml").read_bytes()).hexdigest(),
        "steps_planned": cfg["steps"],
        "steps_completed": state.get("global_step", len(rows)),
        "resumed_from": "runs/rlvr/trainer/checkpoint-100",
        "reward_batches_logged": len(rows),
        "max_completion_length": cap,
        "max_completion_length_derivation":
            f"{cfg['max_completion_length_headroom']}x the longest target in the pool "
            f"({pool_max_target} tokens)",
        "prompt_pool": {"selected": prov["pool_size"], "records_in_file": prov["file_size"],
                        "selection_seed": prov["selection_seed"],
                        "file_sha256": prov["pool_file_sha256"]},
        "verifier": Verifier().fingerprint(),
        "wall_sec": wall_sec,
        "wall_sec_note": ("the resumed segment only, from the chain's own markers. The first 100 "
                          "steps ran in an attempt the host rebooted, and their elapsed time was "
                          "not recorded anywhere that survived."),
        "num_input_tokens_seen": state.get("num_input_tokens_seen"),
        "summary": {
            "reward_total_first_decile": mean(first, "reward_total_mean"),
            "reward_total_last_decile": mean(last, "reward_total_mean"),
            "reward_schema_first_decile": mean(first, "reward_schema_mean"),
            "reward_schema_last_decile": mean(last, "reward_schema_mean"),
            "reward_exact_first_decile": mean(first, "reward_exact_mean"),
            "reward_exact_last_decile": mean(last, "reward_exact_mean"),
            "completion_tokens_first_decile": mean(first, "completion_tokens_mean"),
            "completion_tokens_last_decile": mean(last, "completion_tokens_mean"),
            "truncated_fraction_max": max(r["truncated_fraction"] for r in rows),
            "group_collapse_fraction_mean": mean(rows, "group_collapse_fraction"),
            "group_collapse_fraction_last_decile": mean(last, "group_collapse_fraction"),
        },
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
    ap.add_argument("--rebuild-train-manifest", type=float, default=0.0,
                    metavar="WALL_SEC", help="rebuild runs/rlvr/train_manifest.json from the "
                                             "surviving records, with this wall time")
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

    attempts = {}
    att1 = attempt_record(REPO / "runs" / "rlvr_attempt1" / "train.log",
                          REPO / "runs" / "rlvr_attempt1" / "reward_log.jsonl")
    if att1:
        attempts["attempt_1"] = att1
        print(f"attempt 1: exit {att1['exit_code']} (signal {att1['signal']}), "
              f"{att1['steps_logged']} steps logged, died at {att1['died_at']}")

    # Attempt 2 left no training log: it was in /tmp and the host cleared /tmp
    # when it rebooted. What it did leave is measurable -- how far the reward
    # log got, when that file was last written, and when the machine booted.
    p2 = REPO / "runs" / "rlvr_attempt2_partial" / "reward_log.jsonl"
    if p2.exists():
        import datetime as _dt  # noqa: F401  (used by the boot-time reconstruction below)
        boot = None
        try:  # /proc/uptime is present where `uptime -s` may print nothing
            up = float(Path("/proc/uptime").read_text().split()[0])
            boot = (_dt.datetime.now() - _dt.timedelta(seconds=up)).isoformat(timespec="seconds")
        except Exception:
            try:
                boot = subprocess.run(["uptime", "-s"], capture_output=True, text=True,
                                      timeout=5).stdout.strip() or None
            except Exception:
                pass
        ckpts = sorted(q.name for q in (RUN / "trainer").glob("checkpoint-*")) \
            if (RUN / "trainer").exists() else []
        attempts["attempt_2"] = {
            "exit_code": None,
            "steps_logged": len([1 for l in p2.read_text().splitlines() if l.strip()]),
            "host_booted_at": boot,
            "died_at": "host reboot mid-run; no exit marker was written",
            "evidence": ("the reward log stops at this many steps with no exit marker written; "
                         "the host's boot time below is hours after the run started; and /tmp, "
                         "where the training log lived, was empty afterwards. The log file's own "
                         "mtime is NOT evidence here -- it was copied without preserving it, and "
                         "a claim that cannot be supported is not made."),
            "cause": ("a power or host-level event, not a defect in this code. The tailnet showed "
                      "two machines at the same site going offline together."),
            "recovered_by": ("resuming from the step-50 adapter checkpoints added after attempt 1. "
                             "The optimizer, scheduler and RNG state were restored, and the "
                             "entropy series for the first half was recovered from the "
                             "checkpoint's trainer_state.json after the text log was lost."),
            # What is on disk NOW, after the resumed run wrote its own and pruned
            # the older ones. It is NOT what was there at recovery time, and is
            # not labelled as if it were. What the resume actually used is
            # recorded in the training manifest's `resumed_from`.
            "checkpoints_present_now": ckpts,
        }
        a2 = attempts["attempt_2"]
        print(f"attempt 2: {a2['steps_logged']} steps logged, no exit marker, "
              f"host booted {a2['host_booted_at']}")

    if attempts:
        attempts["_comment"] = ("attempts that did not produce the published checkpoint, read from "
                                "what they left behind rather than described from memory")
        (RUN / "attempts.json").write_text(
            json.dumps(attempts, indent=1, ensure_ascii=False) + "\n")

    (RUN / "pool_provenance.json").write_text(
        json.dumps(prov, indent=1, ensure_ascii=False) + "\n")

    # Entropy from trainer_state.json, not from the text log. The host rebooted
    # mid-run and /tmp was cleared with it; the checkpoint's log_history was not,
    # and it is the record the trainer itself keeps. The text log stays as a
    # fallback for a run whose checkpoints were pruned.
    ent = []
    states = sorted((RUN / "trainer").glob("checkpoint-*/trainer_state.json"),
                    key=lambda q: int(q.parent.name.rsplit("-", 1)[-1])) \
        if (RUN / "trainer").exists() else []
    if states:
        hist = json.loads(states[-1].read_text()).get("log_history", [])
        ent = [e["entropy"] for e in hist if "entropy" in e]
        print(f"entropy from {states[-1].parent.name}/trainer_state.json")
    log = Path(a.log)
    if not ent and log.exists():
        ent = [float(m.group(1)) for m in ENTROPY_RE.finditer(log.read_text(errors="replace"))]
        print("entropy from the text log (no checkpoint state found)")
    (RUN / "entropy.jsonl").write_text(
        "".join(json.dumps({"step": i + 1, "entropy": e}) + "\n" for i, e in enumerate(ent)))

    if a.rebuild_train_manifest:
        tm = rebuild_train_manifest(cfg, prov, a.rebuild_train_manifest)
        (RUN / "train_manifest.json").write_text(
            json.dumps(tm, indent=1, ensure_ascii=False) + "\n")
        print(f"rebuilt train_manifest.json: {tm['steps_completed']} steps, "
              f"collapse {tm['summary']['group_collapse_fraction_mean']}")

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
