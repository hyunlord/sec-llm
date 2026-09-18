"""`make ingest` -- run every source ingester from the committed pins.

Refuses to run without ingest/sources.lock.json. That refusal is the whole
reason the pin file exists: an ingester that silently falls back to fetching
HEAD produces a corpus nobody can reproduce, and does it without saying so.
"""

from __future__ import annotations

import argparse
import importlib
import json
import sys
import time
import traceback
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))

from ingest.common import paths  # noqa: E402
from ingest.sources import SOURCE_ORDER  # noqa: E402

LOCK_PATH = REPO / "ingest" / "sources.lock.json"

MODULES = {
    "cve_list": "ingest.cve_list",
    "nvd": "ingest.nvd",
    "cwe": "ingest.cwe",
    "attack": "ingest.attack",
}


def load_lock() -> dict:
    if not LOCK_PATH.exists():
        print(
            f"ERROR: {LOCK_PATH.relative_to(REPO)} is missing.\n"
            "Ingestion never resolves pins on its own -- that would make the corpus\n"
            "unreproducible without telling anyone. Run `make pin` first.",
            file=sys.stderr,
        )
        raise SystemExit(2)
    try:
        lock = json.loads(LOCK_PATH.read_text())
    except Exception as exc:
        print(f"ERROR: {LOCK_PATH} is not valid JSON: {exc!r}", file=sys.stderr)
        raise SystemExit(2)
    srcs = lock.get("sources") or {}
    if not srcs:
        print("ERROR: sources.lock.json contains no pins", file=sys.stderr)
        raise SystemExit(2)
    return lock


def main(argv=None):
    ap = argparse.ArgumentParser(description="Ingest every pinned source.")
    ap.add_argument("--only", nargs="*", help="run only these source ids")
    ap.add_argument("--force", action="store_true", help="re-download even if cached")
    args = ap.parse_args(argv)

    lock = load_lock()
    sources = lock["sources"]
    todo = [s for s in SOURCE_ORDER if s in sources and (not args.only or s in args.only)]
    if args.only:
        unknown = set(args.only) - set(MODULES)
        if unknown:
            print(f"ERROR: unknown source ids: {sorted(unknown)}", file=sys.stderr)
            raise SystemExit(2)
        missing = [s for s in args.only if s not in sources]
        if missing:
            print(f"ERROR: no pin in the lock file for: {missing}. Run `make pin`.", file=sys.stderr)
            raise SystemExit(2)

    paths.ensure_dirs()
    results = {}
    t_all = time.time()

    for sid in todo:
        print(f"\n{'='*70}\nINGEST {sid}\n{'='*70}", flush=True)
        pin = sources[sid]
        mod = importlib.import_module(MODULES[sid])
        # Rule 4 carried over: two attempts, then record and continue.
        last_err = None
        for attempt in (1, 2):
            try:
                t0 = time.time()
                outcome = mod.ingest(pin, force=args.force)
                # Ingesters return (manifest_path, metrics_dict); the older
                # bare-path return is still accepted so nothing silently breaks.
                if isinstance(outcome, tuple):
                    mpath, metrics = outcome
                else:
                    mpath, metrics = outcome, {}
                results[sid] = {
                    "status": "ok",
                    "manifest": str(Path(mpath).relative_to(REPO)),
                    "wall_seconds": round(time.time() - t0, 1),
                    **metrics,
                }
                last_err = None
                break
            except Exception as exc:
                last_err = exc
                print(f"  attempt {attempt}/2 failed: {exc!r}", flush=True)
                if attempt == 1:
                    traceback.print_exc()
                    time.sleep(5)
        if last_err is not None:
            print(f"  RECORDED AS FAILED after 2 attempts: {last_err!r}", flush=True)
            results[sid] = {
                "status": "failed",
                "error": repr(last_err)[:2000],
                "traceback": traceback.format_exc()[-4000:],
            }

    summary_path = paths.DATA / "ingest_run.json"
    summary_path.write_text(
        json.dumps(
            {
                "sources": results,
                "total_wall_seconds": round(time.time() - t_all, 1),
                "finished_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            },
            indent=2,
            sort_keys=True,
        )
        + "\n"
    )

    print(f"\n{'='*70}\nSUMMARY\n{'='*70}")
    for sid, r in results.items():
        print(f"  {sid:10} {r['status']:7} {r.get('manifest') or r.get('error','')[:90]}")
    failed = [s for s, r in results.items() if r["status"] != "ok"]
    print(f"\ntotal wall {round(time.time()-t_all,1)}s; run detail -> {summary_path.relative_to(REPO)}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
