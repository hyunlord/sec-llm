"""Gate 4 -- the harness proves its own reproducibility before it may score.

Two full evaluation passes on the base model, in two separate processes, with
identical settings. Every generated output must be byte-identical and every score
must be identical. If any output differs, the differing items are reported and the
gate refuses to proceed.

This is the load-bearing gate. Gate 0 showed that on this machine greedy decoding
diverges without VLLM_BATCH_INVARIANT=1 even when requests are issued
sequentially -- 15 samples, 2 distinct outputs. That was one prompt at batch size
one. Gate 4 proves the fix holds at evaluation scale, with a full mix of batch
sizes, prompt lengths, two decoding modes and a grammar backend in the loop.

What is compared, and what is deliberately not:

  compared      outputs.jsonl byte for byte; scores.json with timing removed
  not compared  wall-clock timings, the run id, and the sandbox's container
                seconds -- these are expected to differ and comparing them would
                make the gate fail for the wrong reason
"""

from __future__ import annotations

import argparse
import copy
import json
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from eval.common import RUNS, HarnessError, enforce_env, iter_jsonl, sha256_file, write_json  # noqa: E402
from eval.stats import score_run  # noqa: E402

TIMING_KEYS = ("seconds", "wall", "timings", "run_id", "image_id")


def strip_timing(obj):
    """Remove fields that legitimately differ between two identical runs."""
    if isinstance(obj, dict):
        return {k: strip_timing(v) for k, v in obj.items() if k not in TIMING_KEYS}
    if isinstance(obj, list):
        return [strip_timing(v) for v in obj]
    return obj


def run_pass(run_id: str, extra: list[str]) -> float:
    cmd = [sys.executable, "-m", "eval.runner", "--model", "base", "--run-id", run_id, "--all-tasks", *extra]
    print(f"--- pass {run_id}: {' '.join(cmd)}", flush=True)
    t0 = time.time()
    r = subprocess.run(cmd, cwd=str(Path(__file__).resolve().parents[1]))
    if r.returncode != 0:
        raise HarnessError(f"pass {run_id} failed with exit code {r.returncode}")
    return round(time.time() - t0, 1)


def compare_outputs(a: Path, b: Path) -> dict:
    sa, sb = sha256_file(a / "outputs.jsonl"), sha256_file(b / "outputs.jsonl")
    if sa == sb:
        return {"byte_identical": True, "sha256": sa, "differing_items": [], "n_differing": 0}
    ra = {r["example_id"] + "|" + r["decoding"]: r for r in iter_jsonl(a / "outputs.jsonl")}
    rb = {r["example_id"] + "|" + r["decoding"]: r for r in iter_jsonl(b / "outputs.jsonl")}
    diff = []
    for k in sorted(set(ra) | set(rb)):
        x, y = ra.get(k), rb.get(k)
        if x is None or y is None or x["output_text"] != y["output_text"]:
            diff.append({"key": k,
                         "a": (x or {}).get("output_text", "<missing>")[:200],
                         "b": (y or {}).get("output_text", "<missing>")[:200]})
    return {"byte_identical": False, "sha256_a": sa, "sha256_b": sb,
            "n_differing": len(diff), "differing_items": diff[:50],
            "n_compared": len(set(ra) | set(rb))}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", default="base")
    ap.add_argument("--assert-identical", action="store_true")
    ap.add_argument("--run-a", default="baseline")
    ap.add_argument("--run-b", default="baseline_repeat")
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--max-num-seqs", type=int, default=0, help="passed through to both passes")
    ap.add_argument("--skip-generation", action="store_true", help="compare existing runs only")
    ap.add_argument("--no-sandbox", action="store_true")
    a = ap.parse_args()

    enforce_env()
    extra = (["--limit", str(a.limit)] if a.limit else [])
    if a.max_num_seqs:
        extra += ["--max-num-seqs", str(a.max_num_seqs)]
    wall = {}
    if not a.skip_generation:
        wall[a.run_a] = run_pass(a.run_a, extra)
        wall[a.run_b] = run_pass(a.run_b, extra)

    da, db = RUNS / a.run_a, RUNS / a.run_b
    outs = compare_outputs(da, db)
    print(f"outputs byte-identical: {outs['byte_identical']}"
          + ("" if outs["byte_identical"] else f" ({outs['n_differing']} differing items)"), flush=True)

    sa = score_run(a.run_a, with_sandbox=not a.no_sandbox)
    sb = score_run(a.run_b, with_sandbox=not a.no_sandbox)
    ca, cb = strip_timing(copy.deepcopy(sa)), strip_timing(copy.deepcopy(sb))
    scores_identical = ca == cb
    score_diffs = []
    if not scores_identical:
        for k in sorted(set(ca.get("domain", {})) | set(cb.get("domain", {}))):
            if ca["domain"].get(k) != cb["domain"].get(k):
                score_diffs.append({
                    "group": k,
                    "a_accuracy": ca["domain"].get(k, {}).get("accuracy_over_all_items", {}).get("rate"),
                    "b_accuracy": cb["domain"].get(k, {}).get("accuracy_over_all_items", {}).get("rate"),
                })
    print(f"scores identical (timing excluded): {scores_identical}", flush=True)

    passed = bool(outs["byte_identical"] and scores_identical)
    report = {
        "gate": "Gate 4 -- evaluation determinism",
        "runs": [a.run_a, a.run_b], "wall_seconds": wall,
        "env_required": {k: v for k, v in enforce_env().items()},
        "outputs": outs, "scores_identical": scores_identical, "score_differences": score_diffs,
        "passed": passed,
        "compared": "outputs.jsonl byte for byte; scores.json with timing, run id and image id removed",
        "not_compared": list(TIMING_KEYS),
        "why": ("Gate 0 measured that greedy decoding on this machine is not byte-reproducible without "
                "VLLM_BATCH_INVARIANT=1 (15 sequential samples, 2 distinct outputs). Gate 4 proves the fix "
                "holds at evaluation scale with a full batch mix and both decoding modes."),
    }
    write_json(RUNS / a.run_a / "gate4.json", report)
    write_json(Path(RUNS) / "gate4.json", report)
    print(json.dumps({k: report[k] for k in ("passed", "scores_identical")}, indent=1))
    if a.assert_identical and not passed:
        print("GATE 4 FAILED -- refusing to proceed. Differing items in runs/gate4.json", file=sys.stderr)
        return 1
    print("GATE 4 PASSED" if passed else "GATE 4 NOT PASSED (not asserted)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
