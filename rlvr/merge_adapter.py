# -*- coding: utf-8 -*-
"""Merge the GRPO adapter into the base weights, in a process of its own.

This exists because the first attempt did it inline. `merge_and_unload()`
materialises a second full copy of a 7B model on top of a live trainer --
model, optimizer state, generation buffers, gradients -- and the memory
ceiling killed it while writing shards, after all 200 steps had finished.

Doing it in a separate process is not a workaround for the ceiling. It is the
right shape: the expensive artifact (the adapter) is already on disk, and this
step can be re-run as many times as it takes without repeating two hours of
training.

    python -m rlvr.merge_adapter --adapter runs/rlvr/adapter --out checkpoints/rlvr
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
_REPO_ENTRIES = [p for p in sys.path if p and Path(p).resolve() == REPO]
for _p in _REPO_ENTRIES:
    sys.path.remove(_p)

import torch                                    # noqa: E402
from peft import PeftModel                      # noqa: E402
from transformers import AutoModelForCausalLM, AutoTokenizer  # noqa: E402

sys.path[:0] = _REPO_ENTRIES or [str(REPO)]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--adapter", default="runs/rlvr/adapter")
    ap.add_argument("--out", default="checkpoints/rlvr")
    ap.add_argument("--base", default=None)
    a = ap.parse_args()

    import yaml
    cfg = yaml.safe_load((REPO / "rlvr" / "config.yaml").read_text())
    base = REPO / (a.base or cfg["base_checkpoint"])
    adapter, out = REPO / a.adapter, REPO / a.out

    print(f"base     {base}")
    print(f"adapter  {adapter}")
    model = AutoModelForCausalLM.from_pretrained(base, dtype=torch.bfloat16, device_map="cpu")
    model = PeftModel.from_pretrained(model, adapter, dtype=torch.bfloat16)
    merged = model.merge_and_unload()
    # Shard, so the peak is one shard rather than the whole model, and so the
    # result looks like every other checkpoint the harness loads.
    merged.save_pretrained(out, safe_serialization=True, max_shard_size="4GB")
    AutoTokenizer.from_pretrained(adapter if (adapter / "tokenizer.json").exists() else base
                                  ).save_pretrained(out)
    files = sorted(p.name for p in out.iterdir())
    print(f"wrote {out}: {len(files)} files")
    mpath = REPO / "runs" / "rlvr" / "manifest.json"
    if mpath.exists():
        m = json.loads(mpath.read_text())
        m["merged_path"] = str(out.relative_to(REPO))
        m["merged_files"] = files
        mpath.write_text(json.dumps(m, indent=1, ensure_ascii=False) + "\n")
        print("manifest updated with the merged path")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
