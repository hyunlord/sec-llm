"""Check 06 -- is greedy decoding byte-reproducible on this stack?

Four cells: {sequential, concurrent} x {VLLM_BATCH_INVARIANT off, on}.

The sequential cell is the easy one. The concurrent cell is the one that
matters: five copies of the same prompt are dispatched simultaneously alongside
three unrelated filler prompts, so batch composition -- and therefore reduction
order inside the kernels -- differs between runs. That is where greedy decoding
normally stops being byte-identical.

Byte equality in the concurrent case is NOT required to pass this gate. Measuring
and documenting it is.
"""

from __future__ import annotations

import hashlib
import json
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import _common as C  # noqa: E402
import _vllm  # noqa: E402

CHECK_ID = "06"
CHECK_NAME = "determinism"

TARGET_PROMPT = (
    "Describe, in exactly five sentences, how an attacker exploits an "
    "unauthenticated deserialization endpoint and how a defender detects it."
)
FILLERS = [
    "Write a haiku about network latency.",
    "List the OSI model layers in order.",
    "What is the difference between symmetric and asymmetric encryption?",
]
MAX_TOKENS = 128
REPEATS = 5
RUNS = 3  # how many times we repeat each measurement round


def _h(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:16]


def sequential_round(srv):
    outs, lats = [], []
    for _ in range(REPEATS):
        t, lat = srv.complete(TARGET_PROMPT, max_tokens=MAX_TOKENS, temperature=0.0, top_p=1.0, seed=1234)
        outs.append(t)
        lats.append(lat)
    return outs, lats


def concurrent_round(srv, round_idx):
    """Dispatch REPEATS copies of the target prompt plus fillers all at once.

    The fillers are rotated per round so that the batch the scheduler actually
    forms differs between rounds -- that is the whole point.
    """
    rotated = FILLERS[round_idx % len(FILLERS):] + FILLERS[: round_idx % len(FILLERS)]
    jobs = [(TARGET_PROMPT, True)] * REPEATS + [(f, False) for f in rotated]
    results = [None] * len(jobs)

    def work(i):
        prompt, is_target = jobs[i]
        # Fillers get a different length so they finish at different steps and
        # keep changing the in-flight batch shape.
        mt = MAX_TOKENS if is_target else MAX_TOKENS + 17 * (i % 3)
        t, lat = srv.complete(prompt, max_tokens=mt, temperature=0.0, top_p=1.0, seed=1234)
        results[i] = (t, lat, is_target)

    t0 = time.time()
    with ThreadPoolExecutor(max_workers=len(jobs)) as ex:
        list(ex.map(work, range(len(jobs))))
    wall = round(time.time() - t0, 3)
    outs = [r[0] for r in results if r[2]]
    lats = [r[1] for r in results if r[2]]
    return outs, lats, wall


def measure(srv, label):
    """Run both modes against an already-started server."""
    cell = {}

    print(f"\n--- [{label}] sequential: {REPEATS} identical prompts, one at a time, x{RUNS} rounds ---")
    seq_outputs, seq_lats = [], []
    for r in range(RUNS):
        outs, lats = sequential_round(srv)
        seq_outputs.extend(outs)
        seq_lats.extend(lats)
        print(f"  round {r}: hashes={[_h(o) for o in outs]}")
    seq_hashes = [_h(o) for o in seq_outputs]
    cell["sequential"] = {
        "samples": len(seq_outputs),
        "distinct_outputs": len(set(seq_outputs)),
        "byte_identical": len(set(seq_outputs)) == 1,
        "hashes": seq_hashes,
        "mean_latency_sec": round(sum(seq_lats) / len(seq_lats), 3),
        "sample_output": seq_outputs[0],
    }
    print(f"  => distinct={cell['sequential']['distinct_outputs']} "
          f"byte_identical={cell['sequential']['byte_identical']}")

    print(f"\n--- [{label}] concurrent: {REPEATS} identical + {len(FILLERS)} filler prompts in flight, x{RUNS} rounds ---")
    con_outputs, con_lats, walls = [], [], []
    for r in range(RUNS):
        outs, lats, wall = concurrent_round(srv, r)
        con_outputs.extend(outs)
        con_lats.extend(lats)
        walls.append(wall)
        print(f"  round {r}: wall={wall}s hashes={[_h(o) for o in outs]}")
    cell["concurrent"] = {
        "samples": len(con_outputs),
        "distinct_outputs": len(set(con_outputs)),
        "byte_identical": len(set(con_outputs)) == 1,
        "hashes": [_h(o) for o in con_outputs],
        "mean_latency_sec": round(sum(con_lats) / len(con_lats), 3),
        "mean_round_wall_sec": round(sum(walls) / len(walls), 3),
        "filler_prompts": FILLERS,
        "sample_output": con_outputs[0],
    }
    print(f"  => distinct={cell['concurrent']['distinct_outputs']} "
          f"byte_identical={cell['concurrent']['byte_identical']}")

    # Cross-mode: does concurrency change the answer relative to sequential?
    cell["sequential_matches_concurrent"] = bool(
        set(seq_outputs) and set(seq_outputs) == set(con_outputs) and len(set(seq_outputs)) == 1
    )
    return cell


def run():
    notes = []
    data = {
        "model": C.MODEL_ID,
        "sampling": {"temperature": 0.0, "top_p": 1.0, "seed": 1234, "max_tokens": MAX_TOKENS},
        "repeats_per_round": REPEATS,
        "rounds": RUNS,
        "target_prompt": TARGET_PROMPT,
        "matrix": {},
    }

    prev = C.CHECK_DIR / "05_vllm_serve.json"
    if not prev.exists():
        return {
            "status": C.STATUS_FAIL,
            "data": {"error": "check 05 result not found; cannot pick a usable vLLM config"},
            "notes": ["run check 05 first"],
        }
    cfg = json.loads(prev.read_text())["data"].get("project_default")
    if not cfg:
        return {
            "status": C.STATUS_FAIL,
            "data": {"error": "check 05 found no usable vLLM configuration"},
            "notes": ["determinism cannot be measured without a working server"],
        }
    data["vllm_config"] = cfg
    print(f"using vLLM config from check 05: {cfg}")

    for bi in (False, True):
        label = "batch_invariant_on" if bi else "batch_invariant_off"
        env = {"VLLM_BATCH_INVARIANT": "1"} if bi else {}
        print(f"\n########## {label} ##########")
        srv = _vllm.VLLMServer(
            C.MODEL_ID, cfg["port"] + (1 if bi else 0), cfg["extra_args"], env_extra=env, tag=label
        )
        cell = {"env": env, "extra_args": cfg["extra_args"]}
        try:
            ready, secs, why = srv.start()
            cell["server_ready"] = ready
            cell["startup_seconds"] = secs
            if not ready:
                cell["startup_result"] = why
                cell["log_tail"] = srv.log_tail(80)
                print(f"server failed to start ({why})")
                print(cell["log_tail"])
                if bi:
                    notes.append(
                        "CONFLICT: VLLM_BATCH_INVARIANT=1 could not be combined with the "
                        f"working vLLM configuration ({cfg['name']}). Startup failed: {why}."
                    )
            else:
                cell.update(measure(srv, label))
        except Exception as exc:
            cell["server_ready"] = False
            cell["error"] = repr(exc)
            cell["log_tail"] = srv.log_tail(80)
            print(f"ERROR: {exc!r}")
        finally:
            srv.stop()
        data["matrix"][label] = cell

    off = data["matrix"].get("batch_invariant_off", {})
    on = data["matrix"].get("batch_invariant_on", {})

    # Throughput cost of batch invariance, if both cells produced numbers.
    try:
        a = off["concurrent"]["mean_round_wall_sec"]
        b = on["concurrent"]["mean_round_wall_sec"]
        data["batch_invariant_throughput_cost"] = {
            "concurrent_round_wall_off_sec": a,
            "concurrent_round_wall_on_sec": b,
            "slowdown_x": round(b / a, 3) if a else None,
            "sequential_latency_off_sec": off["sequential"]["mean_latency_sec"],
            "sequential_latency_on_sec": on["sequential"]["mean_latency_sec"],
        }
    except Exception:
        data["batch_invariant_throughput_cost"] = None

    cells_reported = 0
    summary_rows = []
    for label, cell in data["matrix"].items():
        for mode in ("sequential", "concurrent"):
            if mode in cell:
                cells_reported += 1
                summary_rows.append(
                    {
                        "batch_invariant": label.endswith("_on"),
                        "mode": mode,
                        "byte_identical": cell[mode]["byte_identical"],
                        "distinct_outputs": cell[mode]["distinct_outputs"],
                        "samples": cell[mode]["samples"],
                    }
                )
            else:
                summary_rows.append(
                    {
                        "batch_invariant": label.endswith("_on"),
                        "mode": mode,
                        "byte_identical": None,
                        "distinct_outputs": None,
                        "samples": 0,
                        "unmeasured_reason": cell.get("startup_result") or cell.get("error") or "server not ready",
                    }
                )
    data["summary_rows"] = summary_rows
    data["cells_measured"] = cells_reported

    for row in summary_rows:
        notes.append(
            f"{'BI=1' if row['batch_invariant'] else 'BI=0'} / {row['mode']}: "
            + (
                f"byte_identical={row['byte_identical']} "
                f"({row['distinct_outputs']} distinct over {row['samples']} samples)"
                if row["samples"]
                else f"NOT MEASURED -- {row.get('unmeasured_reason')}"
            )
        )
    if data.get("batch_invariant_throughput_cost", {}):
        t = data["batch_invariant_throughput_cost"]
        if t and t.get("slowdown_x"):
            notes.append(
                f"batch-invariant kernels cost {t['slowdown_x']}x on concurrent round wall time "
                f"({t['concurrent_round_wall_off_sec']}s -> {t['concurrent_round_wall_on_sec']}s)"
            )

    # The gate requires all four cells to carry an explicit verdict, which a
    # documented "could not be measured, here is why" satisfies.
    status = C.STATUS_PASS if len(summary_rows) == 4 else C.STATUS_FAIL
    if any(r["samples"] == 0 for r in summary_rows):
        status = C.STATUS_WARN
    return {"status": status, "data": data, "notes": notes}


if __name__ == "__main__":
    sys.exit(C.main(sys.modules[__name__]))
