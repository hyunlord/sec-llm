# -*- coding: utf-8 -*-
"""GRPO on cve_to_cwe, starting from the Cond-2 checkpoint.

This demonstrates that the structure runs. It does not claim an improvement,
and the evaluation afterwards is expected to return "no difference detected" at
200 steps on one seed. A demonstration that includes reporting when it runs
badly is still a demonstration; one that only reports when it runs well is not.

Three things are measured because they are the three ways this fails quietly:

  * **Length drift.** Reward hacking through verbosity is the standard failure
    and it shows first in mean completion length. Logged every step, alongside
    the fraction of completions that hit the cap -- a cap that binds would hide
    the drift it is meant to reveal.
  * **Reward components, separately.** Schema reward saturating while exact
    match stays flat is a different outcome from both rising, and a scalar
    cannot tell them apart.
  * **Group collapse.** When every rollout in a group scores identically the
    advantage is zero and the step teaches nothing. If that fraction is high,
    the task was the wrong choice and the report says so.

Import order note: this repository has a `datasets/` package of its own, which
shadows the installed HuggingFace `datasets` that TRL imports internally. The
repository root is therefore removed from `sys.path` while the third-party
stack loads, and put back afterwards. Nothing in this process imports the
repository's `datasets` package, so the shadowing never returns.
"""

from __future__ import annotations

import os
import sys

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_REPO_ENTRIES = [p for p in sys.path if os.path.abspath(p or ".") == _REPO]
for _p in _REPO_ENTRIES:
    sys.path.remove(_p)

import datasets as hf_datasets            # noqa: E402  installed HF datasets, not ours
import torch                              # noqa: E402
import transformers                       # noqa: E402
import trl                                # noqa: E402
from peft import LoraConfig               # noqa: E402
from transformers import AutoModelForCausalLM, AutoTokenizer, TrainerCallback  # noqa: E402
from trl import GRPOConfig, GRPOTrainer   # noqa: E402

sys.path[:0] = _REPO_ENTRIES or [_REPO]

import argparse                           # noqa: E402
import hashlib                            # noqa: E402
import json                               # noqa: E402
import platform                           # noqa: E402
import statistics                         # noqa: E402
import time                               # noqa: E402
from pathlib import Path                  # noqa: E402

import yaml                               # noqa: E402

from rlvr.verifier import Verifier        # noqa: E402

REPO = Path(_REPO)
RUNS = REPO / "runs" / "rlvr"


def sha256_file(p: Path) -> str:
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def stable_int(s: str, mod: int) -> int:
    return int.from_bytes(hashlib.sha256(s.encode()).digest()[:8], "big") % mod


def load_pool(cfg) -> tuple[list, dict]:
    """Prompts drawn by a named seed, in an order that does not depend on the file."""
    path = REPO / cfg["train_file"]
    rows = [json.loads(line) for line in path.read_text().splitlines() if line.strip()]
    rows.sort(key=lambda r: (stable_int(cfg["selection_seed"] + r["example_id"], 1 << 62),
                             r["example_id"]))
    pool = rows[: cfg["n_prompts"]]
    meta = {"file": cfg["train_file"], "file_sha256": sha256_file(path),
            "records_in_file": len(rows), "selected": len(pool),
            "selection_seed": cfg["selection_seed"],
            "selection": "sha256(seed + example_id), ascending, ties by example_id"}
    return pool, meta


class Recorder:
    """Scores a batch once and hands each component to its own reward function.

    TRL calls one reward function per component, which is what keeps them apart
    in the logs. Scoring twice would double the verifier cost for nothing, so
    the batch is scored on first sight and cached by identity of the completions
    list.
    """

    def __init__(self, verifier: Verifier, tokenizer, num_generations: int, log_path: Path):
        self.v = verifier
        self.tok = tokenizer
        self.g = num_generations
        self.log_path = log_path
        self.cache: dict[int, dict] = {}
        self.step = 0
        self.max_completion_length = None
        self.samples: list[dict] = []

    @staticmethod
    def _text(c) -> str:
        if isinstance(c, str):
            return c
        if isinstance(c, list) and c and isinstance(c[-1], dict):
            return c[-1].get("content", "")
        return str(c)

    def compute(self, completions, target_cwe) -> dict:
        key = id(completions)
        hit = self.cache.get(key)
        if hit is not None:
            return hit
        texts = [self._text(c) for c in completions]
        scored = [self.v.score(t, {"cwe_id": g}) for t, g in zip(texts, target_cwe)]
        lens = [len(self.tok(t, add_special_tokens=False)["input_ids"]) for t in texts]
        rec = {"schema": [s["schema_valid"] for s in scored],
               "exact": [s["exact_match"] for s in scored],
               "texts": texts, "lens": lens, "targets": list(target_cwe)}
        self.cache = {key: rec}                     # only the current batch is needed
        self._log(rec)
        return rec

    def _log(self, rec) -> None:
        self.step += 1
        n, g = len(rec["schema"]), self.g
        groups = [slice(i, i + g) for i in range(0, n, g)] if n >= g else [slice(0, n)]
        totals = [a + b for a, b in zip(rec["schema"], rec["exact"])]
        collapsed = sum(1 for s in groups if len(set(totals[s])) == 1)
        cap = self.max_completion_length
        row = {
            "step": self.step,
            "n_completions": n,
            "n_groups": len(groups),
            "reward_total_mean": round(statistics.fmean(totals), 4),
            "reward_schema_mean": round(statistics.fmean(rec["schema"]), 4),
            "reward_exact_mean": round(statistics.fmean(rec["exact"]), 4),
            "completion_tokens_mean": round(statistics.fmean(rec["lens"]), 2),
            "completion_tokens_median": statistics.median(rec["lens"]),
            "completion_tokens_max": max(rec["lens"]),
            "truncated_fraction": round(sum(1 for x in rec["lens"] if cap and x >= cap) / n, 4),
            "groups_collapsed": collapsed,
            "group_collapse_fraction": round(collapsed / len(groups), 4),
            "group_reward_std_mean": round(
                statistics.fmean([statistics.pstdev(totals[s]) for s in groups]), 4),
        }
        with open(self.log_path, "a") as f:
            f.write(json.dumps(row) + "\n")
        # Keep the highest-reward completions for the manual inspection pass.
        for t, sc, ex, ln, tg in zip(rec["texts"], rec["schema"], rec["exact"],
                                     rec["lens"], rec["targets"]):
            if sc + ex >= 2.0:
                self.samples.append({"step": self.step, "text": t, "target": tg,
                                     "tokens": ln, "reward": sc + ex})

    def reward_schema(self, prompts, completions, target_cwe, **kw):
        return self.compute(completions, target_cwe)["schema"]

    def reward_exact_match(self, prompts, completions, target_cwe, **kw):
        return self.compute(completions, target_cwe)["exact"]


class StepClock(TrainerCallback):
    def __init__(self):
        self.t0 = time.time()
        self.steps = 0

    def on_step_end(self, args, state, control, **kw):
        self.steps = state.global_step


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", default="rlvr/config.yaml")
    ap.add_argument("--steps", type=int, default=None, help="override, for smoke runs")
    ap.add_argument("--out", default=None)
    a = ap.parse_args()

    cfg = yaml.safe_load((REPO / a.config).read_text())
    steps = a.steps if a.steps else cfg["steps"]
    run_dir = Path(a.out) if a.out else RUNS
    run_dir.mkdir(parents=True, exist_ok=True)
    log_path = run_dir / "reward_log.jsonl"
    log_path.write_text("")

    transformers.set_seed(cfg["seed"])
    pool, pool_meta = load_pool(cfg)
    cap = cfg["max_completion_length_headroom"] * max(r["n_target_tokens"] for r in pool)

    base = REPO / cfg["base_checkpoint"]
    tok = AutoTokenizer.from_pretrained(base)
    verifier = Verifier()
    rec = Recorder(verifier, tok, cfg["num_generations"], log_path)
    rec.max_completion_length = cap

    ds = hf_datasets.Dataset.from_list([
        {"prompt": [{"role": "user", "content": r["prompt"]}],
         "target_cwe": r["target"]["cwe_id"],
         "example_id": r["example_id"]}
        for r in pool])

    args = GRPOConfig(
        output_dir=str(run_dir / "trainer"),
        max_steps=steps,
        per_device_train_batch_size=cfg["per_device_train_batch_size"],
        gradient_accumulation_steps=cfg["gradient_accumulation_steps"],
        num_generations=cfg["num_generations"],
        max_completion_length=cap,
        temperature=cfg["temperature"],
        top_p=cfg["top_p"],
        learning_rate=float(cfg["learning_rate"]),
        beta=float(cfg["beta"]),
        loss_type=cfg["loss_type"],
        scale_rewards=cfg["scale_rewards"],
        seed=cfg["seed"],
        bf16=True,
        gradient_checkpointing=True,
        logging_steps=1,
        save_strategy="no",
        report_to=[],
        use_vllm=False,
        log_completions=False,
    )

    model = AutoModelForCausalLM.from_pretrained(base, dtype=torch.bfloat16)
    peft_cfg = LoraConfig(
        r=cfg["lora"]["r"], lora_alpha=cfg["lora"]["alpha"],
        lora_dropout=cfg["lora"]["dropout"],
        target_modules=cfg["lora"]["target_modules"], task_type="CAUSAL_LM")

    clock = StepClock()
    trainer = GRPOTrainer(
        model=model, args=args, train_dataset=ds,
        reward_funcs=[rec.reward_schema, rec.reward_exact_match],
        processing_class=tok, peft_config=peft_cfg, callbacks=[clock])

    t0 = time.time()
    trainer.train()
    wall = time.time() - t0

    # Merge so the P4 harness can load it the same way it loads Cond-1 and Cond-2.
    merged = REPO / "checkpoints" / "rlvr"
    trainer.model.merge_and_unload().save_pretrained(merged, safe_serialization=True)
    tok.save_pretrained(merged)

    rows = [json.loads(x) for x in log_path.read_text().splitlines() if x.strip()]
    first, last = rows[: max(1, len(rows) // 10)], rows[-max(1, len(rows) // 10):]

    def mean(rs, k):
        return round(statistics.fmean(r[k] for r in rs), 4)

    manifest = {
        "name": cfg["name"],
        "task": cfg["task"],
        "claim": ("this run demonstrates that the RLVR structure executes end to end. "
                  "It does not claim a performance improvement; see reports/rlvr.md."),
        "base_checkpoint": cfg["base_checkpoint"],
        # The authoritative digest of the starting weights already exists: the
        # P5 trainer recorded it when it merged them. Re-hashing 15 GB here to
        # produce the same number is waste, and producing a different one would
        # be worse.
        "base_checkpoint_sha256": json.loads(
            (REPO / "runs" / "cond2" / "train_manifest.json").read_text()
        )["merged_checkpoint_sha256"],
        "merged_path": str(merged),
        "config": cfg,
        "config_sha256": hashlib.sha256((REPO / a.config).read_bytes()).hexdigest(),
        "steps_planned": steps,
        "steps_completed": clock.steps,
        "reward_batches_logged": len(rows),
        "max_completion_length": cap,
        "max_completion_length_derivation":
            f"{cfg['max_completion_length_headroom']}x the longest target in the pool "
            f"({max(r['n_target_tokens'] for r in pool)} tokens)",
        "prompt_pool": pool_meta,
        "verifier": verifier.fingerprint(),
        "wall_sec": round(wall, 1),
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
        "env": {
            "python": platform.python_version(), "machine": platform.machine(),
            "torch": torch.__version__, "trl": trl.__version__,
            "transformers": transformers.__version__,
            "gpu_name": torch.cuda.get_device_name(0) if torch.cuda.is_available() else None,
        },
    }
    (run_dir / "manifest.json").write_text(json.dumps(manifest, indent=1, ensure_ascii=False) + "\n")
    (run_dir / "high_reward_samples.jsonl").write_text(
        "".join(json.dumps(s, ensure_ascii=False) + "\n" for s in rec.samples))

    s = manifest["summary"]
    print(f"steps {clock.steps}/{steps} in {wall / 3600:.2f}h")
    print(f"  reward total   {s['reward_total_first_decile']:.3f} -> {s['reward_total_last_decile']:.3f}")
    print(f"  reward schema  {s['reward_schema_first_decile']:.3f} -> {s['reward_schema_last_decile']:.3f}")
    print(f"  reward exact   {s['reward_exact_first_decile']:.3f} -> {s['reward_exact_last_decile']:.3f}")
    print(f"  tokens         {s['completion_tokens_first_decile']:.1f} -> "
          f"{s['completion_tokens_last_decile']:.1f} (cap {cap}, "
          f"max truncated fraction {s['truncated_fraction_max']})")
    print(f"  group collapse {s['group_collapse_fraction_mean']:.3f} mean, "
          f"{s['group_collapse_fraction_last_decile']:.3f} last decile")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
