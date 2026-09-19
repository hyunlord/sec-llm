"""Generate every evaluation output and record exactly how it was produced.

The runner is the only stage that touches a GPU. It writes two files per run:
outputs.jsonl (every generation, raw) and manifest.json (settings, hashes,
versions, timings). Scoring reads those and never regenerates -- so a score is
always traceable to bytes on disk, and re-scoring never requires a GPU.

Order of operations is deliberate:

  1. refuse to start if the required environment is not exactly right
  2. verify the dataset manifest against the files on disk, and abort on drift
  3. hash the checkpoint that is about to be loaded
  4. only then load the model

A score computed against a dataset that has drifted is worse than no score, so
the verification happens before the expensive part, not after.

Every task is generated twice: free generation, and generation constrained to the
task's JSON Schema. The gap between them measures how much of the schema
compliance comes from the model and how much from the decoder. General-ability
items have no schema and are generated once; that asymmetry is recorded.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from eval import strata  # noqa: E402
from eval.common import (  # noqa: E402
    DECODINGS, EVAL_SPLITS, GENERAL, OUT, REQUIRED_SAMPLING, SCHEMAS, SEED, TASKS, VLLM_ENGINE,
    MEMORY_CEILING, MODEL_REPO, HarnessError, checkpoint_digest, enforce_env, eval_file_keys,
    host_facts, iter_jsonl, model_snapshot, pinned_model_commit, run_dir, sha256_text, versions,
    verify_dataset, write_json, write_jsonl,
)
from eval.scorers import general as general_scorer  # noqa: E402

# The generation cap is NOT a number this harness chose. It is whatever context
# the model has left after the prompt.
#
# The first version capped at 2 * max(recorded target tokens) + 32. That was
# data-derived but derived from the wrong distribution: targets are bare JSON,
# while free generation adds prose. Measured on the smoke run, free-mode
# cvss_vector output began "Certainly! Based on the vulnerability description..."
# and hit the cap mid-JSON -- finish_reason "length" -- so schema validity was
# measuring the cap, not the model. That is fatal here, because the free vs
# constrained gap is supposed to measure what the DECODER contributes to schema
# compliance. A cap-induced gap would answer a different question.
#
# So the cap is max_model_len minus the prompt: a property of the model, not a
# level anyone picked. Truncation now means the model did not stop, which is a
# real formatting failure and is counted as one.
MAX_TOKENS_RULE = "max_model_len - prompt tokens - 8, per item; no cap chosen by the harness"
GENERAL_MAX_TOKENS = 8


def load_domain_items(tasks, splits, limit=None) -> dict:
    """{(task, split): [items]} in a fixed order, with the coverage field kept."""
    out = {}
    for t in tasks:
        for sp in splits:
            rows = sorted(iter_jsonl(OUT / t / f"{sp}.jsonl"), key=lambda e: e["example_id"])
            if limit:
                rows = rows[:limit]
            out[(t, sp)] = rows
    return out


def remaining_context(prompt_token_counts, max_model_len: int) -> list[int]:
    # 8 tokens of slack: the harness tokenizes the prompt itself and vLLM
    # recounts it, and the two must not disagree into an over-length request.
    return [max(1, max_model_len - c - 8) for c in prompt_token_counts]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", default="base", help="'base' = the pinned Qwen2.5-7B-Instruct checkpoint")
    ap.add_argument("--run-id", required=True)
    ap.add_argument("--all-tasks", action="store_true")
    ap.add_argument("--tasks", default="", help="comma separated subset of tasks")
    ap.add_argument("--splits", default=",".join(EVAL_SPLITS))
    ap.add_argument("--decoding", default="both", choices=["both", "free", "constrained"])
    ap.add_argument("--general", default="both", choices=["both", "none"] + list(GENERAL))
    ap.add_argument("--limit", type=int, default=0, help="items per (task, split); a smoke run, marked partial")
    ap.add_argument("--no-network", action="store_true", help="general-ability sets must already be pinned")
    ap.add_argument("--max-num-seqs", type=int, default=0,
                    help="override the engine's concurrent-sequence cap; recorded in the manifest. "
                         "Batch invariance is what makes this safe, and Gate 4 proves it at the value used.")
    a = ap.parse_args()

    t_start = time.time()
    env = enforce_env()
    tasks = TASKS if (a.all_tasks or not a.tasks) else tuple(x for x in a.tasks.split(",") if x)
    splits = tuple(x for x in a.splits.split(",") if x)
    modes = DECODINGS if a.decoding == "both" else (a.decoding,)
    gsets = GENERAL if a.general == "both" else (() if a.general == "none" else (a.general,))

    print("[1/6] verifying dataset manifest against disk", flush=True)
    ds = verify_dataset(eval_file_keys(tasks, splits))

    print("[2/6] hashing the pinned checkpoint", flush=True)
    commit = pinned_model_commit()
    snap = model_snapshot(commit)
    ck = checkpoint_digest(snap)

    print("[3/6] loading evaluation items", flush=True)
    domain = load_domain_items(tasks, splits, a.limit or None)
    strata_rec, strat_by_id = {}, {}
    for (t, sp), rows in domain.items():
        st = strata.for_items(rows)
        strata_rec[f"{t}/{sp}"] = {k: v for k, v in st.items() if k != "by_id"}
        strat_by_id.update(st["by_id"])

    gen_items, gen_pins = {}, {}
    for g in gsets:
        prep = general_scorer.prepare(g, allow_network=not a.no_network)
        gen_items[g] = prep["items"]
        gen_pins[g] = prep["pin"]
        print(f"      {g}: {len(prep['items'])} items, revision {prep['pin']['revision'][:12]}", flush=True)

    schemas = {t: json.loads((SCHEMAS / f"{t}.json").read_text()) for t in tasks}

    print("[4/6] loading the model into vLLM", flush=True)
    from transformers import AutoTokenizer
    from vllm import LLM, SamplingParams
    from vllm.sampling_params import StructuredOutputsParams

    tok = AutoTokenizer.from_pretrained(str(snap))
    chat_template = tok.chat_template or ""

    def wrap(prompt: str) -> str:
        return tok.apply_chat_template([{"role": "user", "content": prompt}],
                                       tokenize=False, add_generation_prompt=True)

    engine = dict(VLLM_ENGINE)
    if a.max_num_seqs:
        engine["max_num_seqs"] = a.max_num_seqs
    t_load = time.time()
    so_backend = "xgrammar"
    try:
        llm = LLM(model=str(snap), structured_outputs_config={"backend": so_backend}, **engine)
    except Exception as e:                                     # attempt 2: engine default backend
        print(f"      explicit structured-outputs backend refused ({type(e).__name__}); using engine default", flush=True)
        so_backend = "engine_default"
        llm = LLM(model=str(snap), **engine)
    load_sec = round(time.time() - t_load, 1)
    print(f"      model ready in {load_sec}s", flush=True)

    groups, rows_out, timings = [], [], []
    for t in tasks:
        for sp in splits:
            for mode in modes:
                groups.append(("domain", t, sp, mode))
    for g in gsets:
        groups.append(("general", g, gen_pins[g]["split"], "free"))

    constrained_failures = []
    for kind, t, sp, mode in groups:
        items = domain[(t, sp)] if kind == "domain" else gen_items[t]
        if not items:
            continue
        prompts = [wrap(i["prompt"]) for i in items]
        kw = dict(temperature=REQUIRED_SAMPLING["temperature"], top_p=REQUIRED_SAMPLING["top_p"], seed=SEED)
        if mode == "constrained":
            kw["structured_outputs"] = StructuredOutputsParams(json=schemas[t])
        if kind == "domain":
            n_prompt = [len(x) for x in tok(prompts, add_special_tokens=False)["input_ids"]]
            caps = remaining_context(n_prompt, engine["max_model_len"])
            sparams = [SamplingParams(**kw, max_tokens=c) for c in caps]
            mt = {"min": min(caps), "median": sorted(caps)[len(caps) // 2], "max": max(caps)}
        else:
            sparams = SamplingParams(**kw, max_tokens=GENERAL_MAX_TOKENS)
            mt = {"fixed": GENERAL_MAX_TOKENS}
        t0 = time.time()
        try:
            outs = llm.generate(prompts, sparams)
        except Exception as e:                                  # record and continue, per directive
            constrained_failures.append({"task": t, "split": sp, "mode": mode,
                                         "error": f"{type(e).__name__}: {str(e)[:300]}"})
            print(f"      !! {t}/{sp}/{mode} failed: {type(e).__name__}", flush=True)
            continue
        el = time.time() - t0
        n_in = sum(len(o.prompt_token_ids) for o in outs)
        n_out = sum(len(o.outputs[0].token_ids) for o in outs)
        timings.append({"group": f"{t}/{sp}/{mode}", "items": len(items), "seconds": round(el, 1),
                        "prompt_tokens": n_in, "output_tokens": n_out, "max_tokens": mt,
                        "truncated_at_context": sum(1 for o in outs if o.outputs[0].finish_reason == "length"),
                        "output_tokens_per_sec": round(n_out / el, 1) if el else 0.0})
        print(f"      {t}/{sp}/{mode}: {len(items)} items in {el:.0f}s "
              f"({n_out/max(el,1e-9):.0f} out tok/s, cap={mt})", flush=True)
        for idx, (it, o) in enumerate(zip(items, outs)):
            c = o.outputs[0]
            rows_out.append({
                "example_id": it["example_id"], "task": t, "split": sp, "decoding": mode, "kind": kind,
                "stratum": strat_by_id.get(it["example_id"]) if kind == "domain" else None,
                "prompt_sha256": sha256_text(prompts[idx]),
                "output_text": c.text, "n_output_tokens": len(c.token_ids),
                "finish_reason": c.finish_reason, "n_prompt_tokens": len(o.prompt_token_ids),
            })

    # Deterministic file order, independent of the order the groups happened to run.
    rows_out.sort(key=lambda r: (r["task"], r["split"], r["decoding"], r["example_id"]))
    d = run_dir(a.run_id)
    n, out_sha = write_jsonl(d / "outputs.jsonl", rows_out)

    manifest = {
        "run_id": a.run_id, "model_arg": a.model, "model_repo": MODEL_REPO,
        "model_commit": commit, "model_snapshot": str(snap),
        "model_checkpoint_sha256": ck["model_checkpoint_sha256"],
        "tokenizer_sha256": ck["tokenizer_sha256"],
        "chat_template_sha256": sha256_text(chat_template),
        "checkpoint_files": ck["n_files"], "weight_files": ck["weight_files"],
        "env": env, "sampling": {**REQUIRED_SAMPLING, "seed": SEED},
        "vllm_engine": engine, "structured_outputs_backend": so_backend,
        "vllm_engine_gate0_reference": VLLM_ENGINE,
        "memory_ceiling": MEMORY_CEILING,
        "max_tokens_rule": MAX_TOKENS_RULE, "general_max_tokens": GENERAL_MAX_TOKENS,
        "tasks": list(tasks), "splits": list(splits), "decodings": list(modes),
        "general_sets": list(gsets), "general_pins": gen_pins,
        "strata": strata_rec,
        "dataset": ds, "dataset_manifest_sha256": ds["dataset_manifest_sha256"],
        "outputs_jsonl_sha256": out_sha, "n_outputs": n,
        "partial": bool(a.limit), "limit_per_set": a.limit or None,
        "constrained_failures": constrained_failures,
        "timings": timings,
        "wall": {"model_load_sec": load_sec, "total_sec": round(time.time() - t_start, 1),
                 "generation_sec": round(sum(x["seconds"] for x in timings), 1)},
        **versions(), **host_facts(),
    }
    write_json(d / "manifest.json", manifest)
    print(f"[5/6] wrote {n} outputs -> {d/'outputs.jsonl'} (sha256 {out_sha[:16]}…)")
    print(f"[6/6] wall {manifest['wall']['total_sec']}s "
          f"(generation {manifest['wall']['generation_sec']}s, load {load_sec}s)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
