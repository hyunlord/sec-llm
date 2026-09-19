"""Train one condition. Reproducible by construction; reproducibility CLAIMED only
where it was tested.

Design decisions, each recorded in the run manifest:

  packing     examples are shuffled once under the seed (that order is hashed),
              then greedily packed into 4096-token sequences. Packed sequences
              use a block-diagonal causal mask and per-example position ids, so
              examples in the same sequence cannot attend to each other. Checked
              on this host before this design was adopted: segment-2 logits under
              the mask agree with the example run alone (argmax 1.0), while naive
              packing drifts 7x further. Both numbers are re-measured at run
              start and written to the manifest.
  steps       fixed at 157 for both conditions (P3.2 equal-budget schedule).
              16 sequences per step; the sequences beyond 157*16 are left over
              and counted, exactly as lengths.md described.
  loss        assistant tokens only. The prompt is rendered through the same
              chat template the evaluation harness uses, so train and eval see
              the same tokens.
  precision   base weights bf16, LoRA weights fp32, bf16 autocast; AdamW, linear
              warmup then cosine to zero, gradient clip 1.0.
  merge       the adapter is saved, then merged into the base weights and saved
              as a full bf16 checkpoint. The evaluation harness loads the merged
              checkpoint through the same vLLM path Gate 4 proved deterministic,
              so no LoRA-kernel question enters the comparison.

Warmup check: after 20 steps the mean step time is compared with Gate 0's
129.5 s/step. Over 2x the prediction stops the run and writes the manifest with
status "aborted_warmup"; far under is reported just as loudly.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import random
import shutil
import sys
import time
from pathlib import Path

import yaml

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))

from eval.common import (  # noqa: E402
    MANIFESTS, OUT, HarnessError, checkpoint_digest, host_facts, iter_jsonl, model_snapshot,
    pinned_model_commit, sha256_file, sha256_text, versions, write_json,
)
from train import verify_subset  # noqa: E402

CHECKPOINTS = REPO / "checkpoints"
RUNS = REPO / "runs"
GATE0_SEC_PER_STEP = 129.5
WARMUP_CHECK_STEPS = 20
WARMUP_ABORT_FACTOR = 2.0
IGNORE = -100


def die(msg):
    raise HarnessError(msg)


# ------------------------------------------------------------------ data
def load_examples(files):
    manifest = json.loads((MANIFESTS / "datasets.manifest.json").read_text())["files"]
    consumed, rows = {}, []
    for f in files:
        p = OUT / f
        h = sha256_file(p)
        rec = manifest.get(f)
        if rec is None or rec["sha256"] != h:
            die(f"training file {f} does not match the dataset manifest (disk {h[:16]}, manifest {rec and rec['sha256'][:16]})")
        consumed[f] = {"sha256": h, "count": rec["count"]}
        for e in iter_jsonl(p):
            rows.append({"example_id": e["example_id"], "task": e["task"], "prompt": e["prompt"],
                         "response": e["target_json"]})
    return rows, consumed


def render_pair(tok, prompt, response):
    """Token ids for the full exchange and the length of the prompt prefix.
    The prefix uses the exact call the evaluation harness uses."""
    prefix = tok.apply_chat_template([{"role": "user", "content": prompt}], tokenize=True,
                                     add_generation_prompt=True)
    full = tok.apply_chat_template([{"role": "user", "content": prompt},
                                    {"role": "assistant", "content": response}], tokenize=True)
    if hasattr(prefix, "input_ids"):
        prefix, full = prefix["input_ids"], full["input_ids"]
    prefix, full = list(prefix), list(full)
    aligned = full[:len(prefix)] == prefix
    return full, len(prefix), aligned


def pack(examples, seq_len):
    """Greedy sequential packing in the given order. Returns sequences of
    (ids, labels, segment_ids). Examples longer than seq_len are truncated."""
    seqs, cur, truncated = [], None, 0

    def new():
        return {"ids": [], "labels": [], "seg": [], "n": 0}

    cur = new()
    for k, e in enumerate(examples):
        ids, plen = e["ids"], e["prefix_len"]
        if len(ids) > seq_len:
            truncated += 1
            ids = ids[:seq_len]
        labels = [IGNORE] * min(plen, len(ids)) + ids[min(plen, len(ids)):]
        if cur["ids"] and len(cur["ids"]) + len(ids) > seq_len:
            seqs.append(cur); cur = new()
        cur["ids"].extend(ids); cur["labels"].extend(labels); cur["seg"].extend([cur["n"]] * len(ids)); cur["n"] += 1
    if cur["ids"]:
        seqs.append(cur)
    return seqs, truncated


def to_batch(seqs, seq_len, pad_id, device, dtype):
    import torch
    B = len(seqs)
    ids = torch.full((B, seq_len), pad_id, dtype=torch.long)
    labels = torch.full((B, seq_len), IGNORE, dtype=torch.long)
    seg = torch.full((B, seq_len), -1, dtype=torch.long)
    pos = torch.zeros((B, seq_len), dtype=torch.long)
    for i, s in enumerate(seqs):
        n = len(s["ids"])
        ids[i, :n] = torch.tensor(s["ids"]); labels[i, :n] = torch.tensor(s["labels"])
        sg = torch.tensor(s["seg"]); seg[i, :n] = sg
        # position ids restart at 0 for every packed example
        p = torch.zeros(n, dtype=torch.long)
        start = 0
        for j in range(1, n + 1):
            if j == n or sg[j] != sg[j - 1]:
                p[start:j] = torch.arange(j - start); start = j
        pos[i, :n] = p
    ids, labels, seg, pos = (x.to(device) for x in (ids, labels, seg, pos))
    causal = torch.tril(torch.ones(seq_len, seq_len, dtype=torch.bool, device=device))
    same = seg[:, :, None] == seg[:, None, :]
    eye = torch.eye(seq_len, dtype=torch.bool, device=device)
    allowed = (causal & same) | eye                       # pad rows attend to themselves only
    mask = torch.zeros((B, 1, seq_len, seq_len), dtype=dtype, device=device)
    mask.masked_fill_(~allowed[:, None], torch.finfo(dtype).min)
    return ids, labels, pos, mask


# ---------------------------------------------------------------- checks
def packing_isolation_check(model, tok, device):
    """Re-measure on this host: does the block-diagonal mask isolate packed
    examples? Compares segment-2 logits packed+masked vs alone vs naive."""
    import torch
    a = tok("The vulnerability allows remote attackers to execute arbitrary code via a crafted packet.").input_ids
    b = tok("A buffer overflow in the image parser lets local users gain privileges.").input_ids
    seqs = [{"ids": a + b, "labels": [IGNORE] * (len(a) + len(b)), "seg": [0] * len(a) + [1] * len(b), "n": 2}]
    L = len(a) + len(b)
    ids, _, pos, mask = to_batch(seqs, L, tok.pad_token_id, device, torch.bfloat16)
    model.eval()
    with torch.no_grad(), torch.autocast("cuda", dtype=torch.bfloat16):
        alone = model(torch.tensor([b], device=device)).logits[0].float()
        masked = model(ids, attention_mask=mask, position_ids=pos).logits[0, len(a):].float()
        naive = model(ids).logits[0, len(a):].float()
    model.train()
    return {"max_abs_logit_diff_masked_vs_alone": round((masked - alone).abs().max().item(), 4),
            "max_abs_logit_diff_naive_vs_alone": round((naive - alone).abs().max().item(), 4),
            "argmax_agreement_masked_vs_alone": round((masked.argmax(-1) == alone.argmax(-1)).float().mean().item(), 4)}


def lr_at(step, cfg):
    w, T = cfg["warmup_steps"], cfg["steps"]
    if step < w:
        return cfg["lr"] * (step + 1) / w
    prog = (step - w) / max(1, T - w)
    return cfg["lr"] * 0.5 * (1 + math.cos(math.pi * prog))


# ------------------------------------------------------------------ main
def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", required=True)
    ap.add_argument("--max-steps", type=int, default=0, help="smoke runs only; marks the manifest partial")
    ap.add_argument("--no-merge", action="store_true")
    a = ap.parse_args()
    cfg = yaml.safe_load(Path(a.config).read_text())
    name = cfg["name"]
    if os.environ.get("PIP_ONLY_BINARY") != ":all:":
        die("PIP_ONLY_BINARY=:all: is required (rule 3: no source builds on the training host)")

    import torch
    from peft import LoraConfig, get_peft_model
    from transformers import AutoModelForCausalLM, AutoTokenizer

    t_start = time.time()
    run_dir = RUNS / name; run_dir.mkdir(parents=True, exist_ok=True)
    ck_dir = CHECKPOINTS / name

    print(f"[1/7] subset relation, recomputed from files", flush=True)
    sub = verify_subset.verify()
    if not (sub["subset_holds"] and sub["matches_manifest_record"]):
        die(f"subset check failed: {sub}")

    print(f"[2/7] loading and verifying training files", flush=True)
    rows, consumed = load_examples(cfg["files"])
    rows.sort(key=lambda r: r["example_id"])
    rnd = random.Random(cfg["seed"])
    rnd.shuffle(rows)
    data_order_sha = sha256_text("\n".join(r["example_id"] for r in rows))
    by_task = {}
    for r in rows:
        by_task[r["task"]] = by_task.get(r["task"], 0) + 1

    print(f"[3/7] tokenizing {len(rows):,} examples through the eval chat template", flush=True)
    commit = pinned_model_commit(); snap = model_snapshot(commit)
    tok = AutoTokenizer.from_pretrained(str(snap))
    if tok.pad_token is None:
        tok.pad_token = tok.eos_token
    misaligned = 0
    for r in rows:
        ids, plen, ok = render_pair(tok, r["prompt"], r["response"])
        r["ids"], r["prefix_len"] = ids, plen
        misaligned += (not ok)
    seqs, truncated = pack(rows, cfg["seq_len"])
    per_step = cfg["per_device_batch"] * cfg["grad_accum"]
    steps = a.max_steps or cfg["steps"]
    need = steps * per_step
    if len(seqs) < need:
        die(f"{len(seqs)} packed sequences < {need} needed for {steps} steps")
    used, left = seqs[:need], len(seqs) - need
    tokens_used = sum(len(s["ids"]) for s in used)
    sup_tokens = sum(sum(1 for x in s["labels"] if x != IGNORE) for s in used)
    tokens_all = sum(len(s["ids"]) for s in seqs)
    ex_seen = sum(s["n"] for s in used)
    # Which examples the fixed step budget actually reaches, by task. The P3.2
    # token count excluded the chat template's system prompt and role markers,
    # so 157 steps do not reach every example; this records how far they reach.
    seen_ids = set()
    k = 0
    for s in used:
        seen_ids.update(r["example_id"] for r in rows[k:k + s["n"]]); k += s["n"]
    seen_by_task = {}
    for r in rows:
        if r["example_id"] in seen_ids:
            seen_by_task[r["task"]] = seen_by_task.get(r["task"], 0) + 1
    print(f"      {len(seqs):,} packed sequences, {need:,} used, {left} left over; "
          f"{tokens_used:,} tokens, {sup_tokens:,} supervised; truncated {truncated}; misaligned prefixes {misaligned}", flush=True)

    print(f"[4/7] loading model + LoRA", flush=True)
    device = "cuda"
    model = AutoModelForCausalLM.from_pretrained(str(snap), dtype=torch.bfloat16, attn_implementation="sdpa",
                                                 device_map=device)
    model.config.use_cache = False
    model.gradient_checkpointing_enable(gradient_checkpointing_kwargs={"use_reentrant": False})
    model.enable_input_require_grads()
    lc = cfg["lora"]
    model = get_peft_model(model, LoraConfig(r=lc["r"], lora_alpha=lc["alpha"], lora_dropout=lc["dropout"],
                                             bias="none", task_type="CAUSAL_LM", target_modules=lc["target_modules"]))
    trainable = 0
    for p in model.parameters():
        if p.requires_grad:
            p.data = p.data.float(); trainable += p.numel()
    total = sum(p.numel() for p in model.parameters())
    iso = packing_isolation_check(model, tok, device)
    print(f"      trainable {trainable:,} / {total:,}; packing isolation {iso}", flush=True)

    torch.manual_seed(cfg["seed"]); torch.cuda.manual_seed_all(cfg["seed"])
    opt = torch.optim.AdamW([p for p in model.parameters() if p.requires_grad], lr=cfg["lr"], weight_decay=0.0)

    print(f"[5/7] training {steps} steps x {per_step} sequences", flush=True)
    log, status = [], "completed"
    warmup_report = None
    model.train()
    for step in range(steps):
        lr = lr_at(step, cfg)
        for g in opt.param_groups:
            g["lr"] = lr
        torch.cuda.synchronize(); t0 = time.time()
        opt.zero_grad(set_to_none=True)
        loss_acc, tok_acc = 0.0, 0
        for m in range(cfg["grad_accum"]):
            chunk = used[(step * cfg["grad_accum"] + m) * cfg["per_device_batch"]:
                         (step * cfg["grad_accum"] + m + 1) * cfg["per_device_batch"]]
            ids, labels, pos, mask = to_batch(chunk, cfg["seq_len"], tok.pad_token_id, device, torch.bfloat16)
            with torch.autocast("cuda", dtype=torch.bfloat16):
                out = model(input_ids=ids, attention_mask=mask, position_ids=pos)
            logits = out.logits[:, :-1].float()
            tgt = labels[:, 1:]
            n_sup = int((tgt != IGNORE).sum())
            loss = torch.nn.functional.cross_entropy(logits.reshape(-1, logits.size(-1)), tgt.reshape(-1),
                                                     ignore_index=IGNORE, reduction="sum")
            (loss / max(1, n_sup) / cfg["grad_accum"]).backward()
            loss_acc += loss.item(); tok_acc += n_sup
            del out, logits, loss
        gn = torch.nn.utils.clip_grad_norm_([p for p in model.parameters() if p.requires_grad], cfg["grad_clip"])
        opt.step()
        torch.cuda.synchronize(); dt = time.time() - t0
        rec = {"step": step + 1, "loss": round(loss_acc / max(1, tok_acc), 5), "lr": lr, "grad_norm": round(float(gn), 4),
               "seconds": round(dt, 2), "supervised_tokens": tok_acc,
               "peak_mem_gib": round(torch.cuda.max_memory_allocated() / 2**30, 2)}
        log.append(rec)
        print(f"      step {step+1:3d}/{steps}  loss {rec['loss']:.4f}  lr {lr:.2e}  gn {rec['grad_norm']:.3f}  {dt:.1f}s", flush=True)
        (run_dir / "steps.jsonl").write_text("".join(json.dumps(r) + "\n" for r in log))
        if step + 1 == WARMUP_CHECK_STEPS:
            timed = [r["seconds"] for r in log[1:]]           # step 1 carries compile/alloc cost
            mean = sum(timed) / len(timed)
            warmup_report = {"steps_measured": len(timed), "mean_sec_per_step": round(mean, 2),
                             "gate0_prediction_sec_per_step": GATE0_SEC_PER_STEP,
                             "ratio_observed_over_predicted": round(mean / GATE0_SEC_PER_STEP, 3),
                             "projected_hours_for_run": round(mean * steps / 3600, 2),
                             "abort_factor": WARMUP_ABORT_FACTOR}
            print(f"      WARMUP CHECK: {mean:.1f} s/step vs Gate 0 {GATE0_SEC_PER_STEP} "
                  f"(x{warmup_report['ratio_observed_over_predicted']}); projected {warmup_report['projected_hours_for_run']} h", flush=True)
            if mean > WARMUP_ABORT_FACTOR * GATE0_SEC_PER_STEP:
                status = "aborted_warmup"
                print("      observed cost exceeds 2x the prediction; stopping as the work order requires", flush=True)
                break

    manifest = {
        "name": name, "status": status, "config": cfg, "config_sha256": sha256_file(Path(a.config)),
        "steps_completed": len(log), "steps_planned": steps, "partial": bool(a.max_steps),
        "seed": cfg["seed"], "packing_seed": cfg["seed"], "data_order_sha256": data_order_sha,
        "examples": len(rows), "examples_by_task": by_task,
        "packed_sequences": len(seqs), "sequences_used": len(used), "sequences_left_over": left,
        "tokens_in_used_sequences": tokens_used, "supervised_tokens": sup_tokens,
        "tokens_in_all_packed_sequences": tokens_all,
        "examples_seen": ex_seen, "examples_seen_by_task": seen_by_task,
        "epoch_fraction": round(ex_seen / len(rows), 4),
        "schedule_note": ("P3.2 counted prompt+target tokens only (9,960,190 for Cond-1). The chat template adds a "
                          "system prompt and role markers per example, so the same examples pack into more "
                          "4096-token sequences than the schedule assumed. Steps stay at 157 as specified; "
                          "both conditions therefore see the same token budget and the same fraction of "
                          "their data, and neither sees a full epoch. epoch_fraction is the measured value."),
        "truncated_over_seq_len": truncated, "misaligned_prefixes": misaligned,
        "files_consumed": consumed, "subset_check": sub,
        "model_repo_commit": commit, "base_checkpoint_sha256": checkpoint_digest(snap)["model_checkpoint_sha256"],
        "trainable_params": trainable, "total_params": total,
        "packing_isolation_check": iso, "warmup_check": warmup_report,
        "loss_first": log[0]["loss"] if log else None, "loss_last": log[-1]["loss"] if log else None,
        "mean_sec_per_step_after_first": (round(sum(r["seconds"] for r in log[1:]) / max(1, len(log) - 1), 2) if len(log) > 1 else None),
        "peak_mem_gib": max((r["seconds"] and r["peak_mem_gib"]) for r in log) if log else None,
        "reproducibility_claim": ("seed, data order hash and packing seed are recorded; bit-identical re-training "
                                  "was NOT re-run and is therefore untested"),
        **versions(), **host_facts(),
    }
    if status != "completed":
        manifest["wall_sec"] = round(time.time() - t_start, 1)
        write_json(run_dir / "train_manifest.json", manifest)
        return 2

    print(f"[6/7] saving adapter and merged checkpoint", flush=True)
    if ck_dir.exists():
        shutil.rmtree(ck_dir)
    (ck_dir / "adapter").mkdir(parents=True)
    model.save_pretrained(str(ck_dir / "adapter"))
    ad = checkpoint_digest(ck_dir / "adapter")
    manifest["adapter_sha256"] = ad["model_checkpoint_sha256"]; manifest["adapter_files"] = ad["n_files"]
    if not a.no_merge:
        merged = model.merge_and_unload()
        merged = merged.to(torch.bfloat16)
        merged.save_pretrained(str(ck_dir / "merged"), safe_serialization=True)
        tok.save_pretrained(str(ck_dir / "merged"))
        md = checkpoint_digest(ck_dir / "merged")
        manifest["merged_checkpoint_sha256"] = md["model_checkpoint_sha256"]; manifest["merged_files"] = md["n_files"]
        manifest["merged_path"] = str(ck_dir / "merged")
    manifest["wall_sec"] = round(time.time() - t_start, 1)
    write_json(run_dir / "train_manifest.json", manifest)
    print(f"[7/7] done: {name} in {manifest['wall_sec']/3600:.2f} h; adapter {manifest['adapter_sha256'][:16]}…"
          + (f" merged {manifest['merged_checkpoint_sha256'][:16]}…" if not a.no_merge else ""), flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
