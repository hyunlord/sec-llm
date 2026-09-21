# -*- coding: utf-8 -*-
"""Run a comparison into a named file without destroying `runs/compare.json`.

`eval.stats.compare_multi` always writes `runs/compare.json`. That file is the
P5.1 record and the source the published documents read, so any comparison
added later has to be taken without touching it: copy it aside with its digest,
call the function unchanged, move the returned record to the requested path,
restore, and verify the restore byte for byte.

`eval/` is not modified. It is the code that produced the published numbers.

The protection is deliberately duplicated from `tools/seed2_finalize.py` rather
than factored out of it: that script has already run and its output is
committed, and refactoring a verified artifact to save nine lines trades a real
risk for a cosmetic gain.

    python -m tools.compare_into --out runs/compare_rlvr.json baseline cond2 rlvr
"""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))

PROTECTED = REPO / "runs" / "compare.json"


def sha(p: Path) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest()


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("runs", nargs="+", help="baseline first")
    ap.add_argument("--out", required=True)
    a = ap.parse_args()

    for r in a.runs:
        for f in ("scores.json", "flags.json"):
            if not (REPO / "runs" / r / f).exists():
                raise SystemExit(f"refusing to run: runs/{r}/{f} is missing -- score the run first")

    digest, backup = None, None
    if PROTECTED.exists():
        digest = sha(PROTECTED)
        backup = PROTECTED.with_suffix(".json.bak")
        shutil.copy2(PROTECTED, backup)
        print(f"[1/3] runs/compare.json copied aside ({digest[:16]}…)")

    from eval.stats import compare_multi

    damaged = False
    try:
        rec = compare_multi(list(a.runs))
        out = REPO / a.out
        out.write_text(json.dumps(rec, indent=1, ensure_ascii=False, sort_keys=True) + "\n")
        print(f"[2/3] wrote {a.out}")
        for g, v in rec["general"].items():
            first = list(v["pairs"])[0]
            print(f"      {g}: {first} -> {v['pairs'][first]['verdict']}")
    finally:
        if backup is not None:
            shutil.copy2(backup, PROTECTED)
            if sha(PROTECTED) != digest:
                print("RESTORE FAILED -- runs/compare.json may be damaged; "
                      f"the copy is at {backup}", file=sys.stderr)
                damaged = True
            else:
                backup.unlink()

    if damaged:
        return 1
    print("[3/3] runs/compare.json restored and verified byte-identical")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
