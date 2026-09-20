# -*- coding: utf-8 -*-
"""Produce the seed-5678 comparison records. Run on the DGX after SEED2 DONE.

Two things in `eval/` write to fixed paths and would destroy the P5.1 record if
called naively:

  * `eval.stats.compare_multi` always writes `runs/compare.json`
  * `eval.probe.rebuild` / `score_rebuilt` always write `runs/probe/rebuilt_*.json`

This wrapper does not change either of them. `eval/` is the code that produced
the published numbers and it stays exactly as it was; instead each function is
called, its returned record is written to a new path, and the file it clobbered
is restored from a copy taken beforehand and checked by digest. If a restore
does not match, the script says so and exits non-zero rather than leaving the
record in an unknown state.

`eval.probe.COND_FILES` has no entry for the seed-2 conditions. The entry is
injected rather than edited in, and it points at the seed-1 files because that
is the fact: seed 5678 trained on exactly the same data, and only the random
seed differs. If that ever stops being true this injection is where it breaks,
loudly.

Three records come out, and the third is the one the single-seed caveat
actually needs:

  runs/compare_seed2.json          baseline, cond1_s2, cond2_s2
  runs/compare_seedvar_cond1.json  baseline, cond1, cond1_s2
  runs/compare_seedvar_cond2.json  baseline, cond2, cond2_s2

The seedvar records measure seed-to-seed movement directly -- same condition,
same evaluation items, different dice -- instead of inferring it from two
separate comparisons.

    python -m tools.seed2_finalize
"""

from __future__ import annotations

import hashlib
import json
import shutil
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))

RUNS = REPO / "runs"
PROBE = RUNS / "probe"

COMPARES = [
    ("compare_seed2.json", ["baseline", "cond1_s2", "cond2_s2"]),
    ("compare_seedvar_cond1.json", ["baseline", "cond1", "cond1_s2"]),
    ("compare_seedvar_cond2.json", ["baseline", "cond2", "cond2_s2"]),
]
PROTECTED = [RUNS / "compare.json", PROBE / "rebuilt_sets.json", PROBE / "rebuilt_scores.json"]
S2_CONDS = ["cond1_s2", "cond2_s2"]


def sha(p: Path) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest()


def require_training_finished() -> None:
    for c in S2_CONDS:
        m = RUNS / c / "train_manifest.json"
        if not m.exists():
            raise SystemExit(f"refusing to run: {m} does not exist yet")
        d = json.loads(m.read_text())
        if d.get("status") != "completed" or d.get("partial"):
            raise SystemExit(f"refusing to run: {c} training is {d.get('status')!r}, partial={d.get('partial')}")
        if d["config"]["seed"] == 1234:
            raise SystemExit(f"refusing to run: {c} carries seed 1234 -- that is not a second seed")
    for c in S2_CONDS:
        for f in ("scores.json", "flags.json", "outputs.jsonl"):
            if not (RUNS / c / f).exists():
                raise SystemExit(f"refusing to run: runs/{c}/{f} is missing -- score the run first")
        if not (RUNS / f"{c}_probe" / "outputs.jsonl").exists():
            raise SystemExit(f"refusing to run: runs/{c}_probe/outputs.jsonl is missing")
    print("[1/5] seed-5678 training and scoring complete for both conditions")


def main() -> int:
    require_training_finished()

    baseline_digests = {p: sha(p) for p in PROTECTED if p.exists()}
    backups = {}
    for p in baseline_digests:
        b = p.with_suffix(p.suffix + ".seed1bak")
        shutil.copy2(p, b)
        backups[p] = b
    print(f"[2/5] {len(backups)} seed-1 records copied aside and digested")

    from eval import probe as probe_mod
    from eval.stats import compare_multi

    written = []
    try:
        for name, runs in COMPARES:
            rec = compare_multi(runs)
            out = RUNS / name
            out.write_text(json.dumps(rec, indent=1, ensure_ascii=False, sort_keys=True) + "\n")
            written.append(out)
            g = rec["general"]
            print(f"[3/5] {name}: " + "; ".join(
                f"{b} {list(v['pairs'])[0]} -> {v['pairs'][list(v['pairs'])[0]]['verdict']}"
                for b, v in g.items()))

        # Seed 5678 trained on the same files as seed 1234. Stated here, not edited
        # into eval/probe.py, so the assumption is visible at the call site.
        probe_mod.COND_FILES["cond1_s2"] = probe_mod.COND_FILES["cond1"]
        probe_mod.COND_FILES["cond2_s2"] = probe_mod.COND_FILES["cond2"]
        probe_mod.rebuild(S2_CONDS)
        rec = probe_mod.score_rebuilt(S2_CONDS)
        for src, dst in ((PROBE / "rebuilt_sets.json", PROBE / "rebuilt_sets_seed2.json"),
                         (PROBE / "rebuilt_scores.json", PROBE / "rebuilt_scores_seed2.json")):
            shutil.copy2(src, dst)
            written.append(dst)
        for c, r in rec["conditions"].items():
            m = r["modes"]["constrained"]
            print(f"[4/5] probe {c}: in-training {r['n_probe_in_training']}, "
                  f"matched {r['n_with_matched_control']}, above floor "
                  f"{100 * m['above_floor']:+.1f}pp (MDD ±{100 * m['condition']['mdd_points']:.1f}pp)")
    finally:
        # Restore whatever the eval functions overwrote, and prove it. No return
        # in here: a restore failure must not swallow an exception that is on its
        # way out. The flag is checked once the block has unwound.
        damaged = []
        for p, b in backups.items():
            shutil.copy2(b, p)
            if sha(p) != baseline_digests[p]:
                damaged.append(p)
            else:
                b.unlink()
        if damaged:
            print("RESTORE FAILED -- the seed-1 records may be damaged: "
                  + ", ".join(str(p) for p in damaged), file=sys.stderr)
            print("the .seed1bak copies are still on disk", file=sys.stderr)

    if damaged:
        return 1

    print(f"[5/5] seed-1 records restored and verified byte-identical "
          f"({len(baseline_digests)} files)")
    for p in written:
        print(f"      wrote {p.relative_to(REPO)}")
    print("\nnext: commit these, pull on the laptop, then `make docs`")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
