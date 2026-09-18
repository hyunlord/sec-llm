"""Check 07 -- what does one LoRA optimizer step actually cost here?

A 20-step LoRA smoke on synthetic data shaped like the real task (instruction
in, fixed-schema JSON out). The output of this check -- seconds per optimizer
step, and the epoch-hour extrapolations derived from it -- is the number the
Phase 5 plan is built on, so it is measured rather than estimated.

On OOM the configuration steps down in a fixed order and the first one that
fits is recorded. QLoRA is deliberately not in that ladder.
"""

from __future__ import annotations

import gc
import json
import random
import shutil
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import _common as C  # noqa: E402

CHECK_ID = "07"
CHECK_NAME = "lora_step_cost"

STEPS = 20
WARMUP_STEPS = 3  # excluded from the timing average: first steps include compile/alloc
TARGET_MODULES = ["q_proj", "k_proj", "v_proj", "o_proj", "gate_proj", "up_proj", "down_proj"]
OUT_DIR = C.REPO / "logs" / "lora_smoke_out"

# Step-down ladder, in the order the work order specifies. QLoRA is not here.
LADDER = [
    {"batch": 4, "grad_accum": 4, "seq_len": 4096, "lora_r": 64},
    {"batch": 2, "grad_accum": 8, "seq_len": 4096, "lora_r": 64},
    {"batch": 2, "grad_accum": 8, "seq_len": 2048, "lora_r": 64},
    {"batch": 2, "grad_accum": 8, "seq_len": 2048, "lora_r": 32},
]

EPOCH_SIZES = [10_000, 30_000, 60_000]


def synth_dataset(tok, n, seq_len, seed=7):
    """Instruction in, fixed-schema JSON out -- padded to a full seq_len block
    so the measured step cost is the worst case, not an average over short rows."""
    rng = random.Random(seed)
    cwes = ["CWE-79", "CWE-89", "CWE-120", "CWE-502", "CWE-287", "CWE-22"]
    sevs = ["low", "medium", "high", "critical"]
    rows = []
    for i in range(n):
        cwe = rng.choice(cwes)
        sev = rng.choice(sevs)
        instruction = (
            "Analyze the following vulnerability report and return the structured "
            "classification as JSON.\n\nReport: "
            + ("A remote attacker can trigger unchecked input handling in the request "
               "parser, leading to memory corruption under specific header lengths. " * 12)
            + f"\nReference {i}."
        )
        answer = json.dumps(
            {
                "cwe_id": cwe,
                "severity": sev,
                "summary": "Unchecked input handling in the request parser allows memory corruption.",
                "remediation": "Bound-check header lengths and reject oversized inputs.",
            },
            ensure_ascii=False,
        )
        text = tok.apply_chat_template(
            [{"role": "user", "content": instruction}, {"role": "assistant", "content": answer}],
            tokenize=False,
        )
        rows.append({"text": text})
    from datasets import Dataset

    ds = Dataset.from_list(rows)

    def tokenize(batch):
        enc = tok(
            batch["text"],
            truncation=True,
            padding="max_length",
            max_length=seq_len,
            return_tensors=None,
        )
        enc["labels"] = [list(x) for x in enc["input_ids"]]
        return enc

    return ds.map(tokenize, batched=True, remove_columns=["text"])


def attempt(cfg):
    import torch
    from peft import LoraConfig, get_peft_model
    from transformers import (
        AutoModelForCausalLM,
        AutoTokenizer,
        DataCollatorForSeq2Seq,
        Trainer,
        TrainingArguments,
    )

    torch.cuda.empty_cache()
    torch.cuda.reset_peak_memory_stats()

    tok = AutoTokenizer.from_pretrained(C.MODEL_ID)
    if tok.pad_token is None:
        tok.pad_token = tok.eos_token

    n_rows = cfg["batch"] * cfg["grad_accum"] * (STEPS + 2)
    ds = synth_dataset(tok, n_rows, cfg["seq_len"])

    try:
        model = AutoModelForCausalLM.from_pretrained(
            C.MODEL_ID, dtype=torch.bfloat16, attn_implementation="sdpa", device_map="cuda"
        )
    except TypeError:
        model = AutoModelForCausalLM.from_pretrained(
            C.MODEL_ID, torch_dtype=torch.bfloat16, attn_implementation="sdpa", device_map="cuda"
        )
    model.config.use_cache = False
    model.enable_input_require_grads()

    peft_cfg = LoraConfig(
        r=cfg["lora_r"],
        lora_alpha=cfg["lora_r"] * 2,
        lora_dropout=0.0,
        bias="none",
        task_type="CAUSAL_LM",
        target_modules=TARGET_MODULES,
    )
    model = get_peft_model(model, peft_cfg)
    trainable = sum(p.numel() for p in model.parameters() if p.requires_grad)
    total = sum(p.numel() for p in model.parameters())
    print(f"trainable params: {trainable:,} / {total:,} ({100*trainable/total:.4f}%)")

    if OUT_DIR.exists():
        shutil.rmtree(OUT_DIR, ignore_errors=True)

    args = TrainingArguments(
        output_dir=str(OUT_DIR),
        per_device_train_batch_size=cfg["batch"],
        gradient_accumulation_steps=cfg["grad_accum"],
        max_steps=STEPS,
        learning_rate=1e-4,
        optim="adamw_torch",
        bf16=True,
        gradient_checkpointing=True,
        gradient_checkpointing_kwargs={"use_reentrant": False},
        logging_steps=1,
        save_strategy="no",
        report_to=[],
        dataloader_num_workers=2,
        remove_unused_columns=False,
        seed=1234,
    )

    step_times = []

    from transformers import TrainerCallback

    class StepTimer(TrainerCallback):
        def on_step_begin(self, *a, **k):
            self._t = time.time()

        def on_step_end(self, *a, **k):
            step_times.append(time.time() - self._t)

    collator = DataCollatorForSeq2Seq(tok, padding=False, return_tensors="pt")
    trainer = Trainer(
        model=model,
        args=args,
        train_dataset=ds,
        data_collator=collator,
        callbacks=[StepTimer()],
    )

    t0 = time.time()
    train_out = trainer.train()
    wall = time.time() - t0

    timed = step_times[WARMUP_STEPS:] or step_times
    sec_per_step = sum(timed) / len(timed)
    tokens_per_step = cfg["batch"] * cfg["grad_accum"] * cfg["seq_len"]
    result = {
        "config": cfg,
        "lora_alpha": cfg["lora_r"] * 2,
        "target_modules": TARGET_MODULES,
        "steps": STEPS,
        "warmup_steps_excluded": WARMUP_STEPS,
        "trainable_params": trainable,
        "total_params": total,
        "wall_seconds": round(wall, 2),
        "sec_per_optimizer_step": round(sec_per_step, 4),
        "all_step_seconds": [round(t, 4) for t in step_times],
        "examples_per_optimizer_step": cfg["batch"] * cfg["grad_accum"],
        "tokens_per_optimizer_step": tokens_per_step,
        "tokens_per_second": round(tokens_per_step / sec_per_step, 1),
        "examples_per_second": round(cfg["batch"] * cfg["grad_accum"] / sec_per_step, 3),
        "final_train_loss": float(train_out.training_loss),
        "peak_allocated_gib": round(torch.cuda.max_memory_allocated() / 2**30, 2),
        "peak_reserved_gib": round(torch.cuda.max_memory_reserved() / 2**30, 2),
    }

    ex_per_step = cfg["batch"] * cfg["grad_accum"]
    result["epoch_extrapolation"] = {
        str(n): {
            "optimizer_steps": round(n / ex_per_step, 1),
            "hours": round(n / ex_per_step * sec_per_step / 3600, 2),
        }
        for n in EPOCH_SIZES
    }

    del trainer, model
    gc.collect()
    torch.cuda.empty_cache()
    shutil.rmtree(OUT_DIR, ignore_errors=True)  # the work order says delete the checkpoint
    return result


def run():
    import torch

    notes = []
    data = {
        "model": C.MODEL_ID,
        "fixed": {
            "dtype": "bfloat16",
            "attn_implementation": "sdpa",
            "optimizer": "adamw_torch",
            "learning_rate": 1e-4,
            "gradient_checkpointing": True,
            "lora_alpha_rule": "2 * r",
            "target_modules": TARGET_MODULES,
        },
        "ladder": LADDER,
        "attempts": [],
    }

    chosen = None
    for i, cfg in enumerate(LADDER):
        print(f"\n=== LoRA attempt {i}: {cfg} ===")
        try:
            r = attempt(cfg)
            r["ok"] = True
            data["attempts"].append(r)
            chosen = r
            print(f"OK: {r['sec_per_optimizer_step']}s/step, "
                  f"peak alloc {r['peak_allocated_gib']} GiB, reserved {r['peak_reserved_gib']} GiB")
            break
        except torch.cuda.OutOfMemoryError as exc:
            print(f"OOM at {cfg}: {exc}")
            data["attempts"].append({"config": cfg, "ok": False, "error": "OutOfMemoryError", "detail": str(exc)[:600]})
            notes.append(f"OOM at batch={cfg['batch']} seq={cfg['seq_len']} r={cfg['lora_r']}; stepping down")
            gc.collect()
            torch.cuda.empty_cache()
        except Exception as exc:
            msg = repr(exc)
            oomish = "out of memory" in msg.lower() or "OutOfMemory" in msg
            print(f"{'OOM-like' if oomish else 'ERROR'} at {cfg}: {msg[:600]}")
            data["attempts"].append({"config": cfg, "ok": False, "error": msg[:1500]})
            gc.collect()
            torch.cuda.empty_cache()
            if not oomish:
                notes.append(f"non-OOM failure at {cfg}: {msg[:300]}")
                break
            notes.append(f"OOM-like failure at {cfg}; stepping down")

    data["chosen"] = chosen
    if chosen:
        c = chosen["config"]
        notes.append(
            f"first configuration that fits: batch={c['batch']} x grad_accum={c['grad_accum']} "
            f"(effective {c['batch']*c['grad_accum']}), seq_len={c['seq_len']}, "
            f"LoRA r={c['lora_r']} alpha={chosen['lora_alpha']}"
        )
        notes.append(
            f"{chosen['sec_per_optimizer_step']}s per optimizer step, "
            f"{chosen['tokens_per_second']} tokens/s, "
            f"peak allocated {chosen['peak_allocated_gib']} GiB / reserved {chosen['peak_reserved_gib']} GiB"
        )
        for n, v in chosen["epoch_extrapolation"].items():
            notes.append(f"one epoch over {int(n):,} examples: {v['optimizer_steps']} steps, ~{v['hours']} h")
        notes.append("training checkpoint deleted; this smoke produces no usable adapter")
    else:
        notes.append("no configuration in the ladder completed 20 steps")

    return {"status": C.STATUS_PASS if chosen else C.STATUS_FAIL, "data": data, "notes": notes}


if __name__ == "__main__":
    sys.exit(C.main(sys.modules[__name__]))
