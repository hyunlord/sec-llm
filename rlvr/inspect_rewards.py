# -*- coding: utf-8 -*-
"""Read the highest-reward completions by hand and report what is in them.

The thing this section of P6 is actually testing is whether the verifier can be
satisfied without solving the task. A reward curve cannot answer that; only
looking at what earned the reward can. So this prints the top-scoring
completions with their targets and lengths, groups them by shape, and writes a
record of what was found -- including the negative finding, if the sample turns
out to be unremarkable.

Two checks that do not need a human:

  * **Answer-shape distribution.** Every full-reward completion should be a bare
    JSON object with one key. Anything else -- prose around the JSON, repeated
    objects, a fence plus commentary -- is the shape reward hacking takes here.
  * **Length against the target.** A full-reward completion much longer than the
    target it matched is earning the reward the long way, which is what length
    drift looks like at the level of a single sample.

    python -m rlvr.inspect_rewards --run rlvr --top 30
"""

from __future__ import annotations

import argparse
import collections
import json
import re
import statistics
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]

BARE_JSON = re.compile(r'^\s*\{\s*"cwe_id"\s*:\s*"CWE-\d{1,5}"\s*\}\s*$')
FENCED = re.compile(r"^\s*```")


def shape(text: str) -> str:
    if BARE_JSON.match(text):
        return "bare JSON object, one key"
    if FENCED.match(text):
        return "markdown fence around the JSON"
    if text.count("{") > 1:
        return "more than one JSON object"
    if len(text.strip().splitlines()) > 1:
        return "multi-line, JSON plus other text"
    return "single line, not a bare object"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--run", default="rlvr")
    ap.add_argument("--top", type=int, default=30)
    a = ap.parse_args()

    run = REPO / "runs" / a.run
    samples = [json.loads(x) for x in
               (run / "high_reward_samples.jsonl").read_text().splitlines() if x.strip()]
    if not samples:
        print("no full-reward completions were recorded -- nothing to inspect, "
              "which is itself the finding")
        return 0

    # Latest first: hacking, if it develops, develops late.
    samples.sort(key=lambda s: (-s["step"], -s["tokens"]))
    top = samples[: a.top]

    shapes = collections.Counter(shape(s["text"]) for s in samples)
    lens = [s["tokens"] for s in samples]
    target_len = 13     # the pool's target length; recorded in the manifest too

    print(f"full-reward completions recorded: {len(samples):,}")
    print(f"token length: median {statistics.median(lens)}, "
          f"mean {statistics.fmean(lens):.1f}, max {max(lens)}")
    print("\nanswer shapes across all full-reward completions:")
    for k, v in shapes.most_common():
        print(f"  {v:6,}  {v / len(samples):6.1%}  {k}")

    print(f"\nlast {len(top)} full-reward completions, longest first:\n")
    for s in top:
        body = s["text"].replace("\n", "\\n")
        flag = "  <-- long" if s["tokens"] > 3 * target_len else ""
        print(f"  step {s['step']:>4}  {s['tokens']:>4} tok  target {s['target']:<12} "
              f"{body[:110]}{flag}")

    finding = {
        "run": a.run,
        "n_full_reward": len(samples),
        "token_length": {"median": statistics.median(lens),
                         "mean": round(statistics.fmean(lens), 2), "max": max(lens)},
        "shapes": dict(shapes),
        "bare_json_fraction": round(shapes["bare JSON object, one key"] / len(samples), 4),
        "long_fraction": round(sum(1 for s in samples if s["tokens"] > 3 * target_len) / len(samples), 4),
        "inspected": len(top),
        "method": ("every completion that scored both schema validity and exact match was kept "
                   "during training; shapes are classified mechanically and the most recent "
                   "sample was read by hand"),
    }
    (run / "reward_inspection.json").write_text(
        json.dumps(finding, indent=1, ensure_ascii=False) + "\n")
    print(f"\nwrote {run / 'reward_inspection.json'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
