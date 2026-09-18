"""Run checks 01..08 in order, merge their results into env/gate0.json, and
regenerate reports/env-report.md from that JSON.

Each check runs in its own process so that a segfault in one (which is exactly
what a CUDA ABI mismatch looks like) does not take the rest of the gate with it.
Raw stdout of every check lands in logs/<id>_<name>.log, which is what `make
pack` ships.
"""

from __future__ import annotations

import json
import os
import platform
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import _common as C  # noqa: E402
import _limits  # noqa: E402
import render_determinism  # noqa: E402
import render_report  # noqa: E402

# Ordered so blast radius increases monotonically. 07 is the heaviest and runs
# last: if it takes the host down despite the ceiling, seven results are already
# on disk. 08 is cheap and moves ahead of it for the same reason.
#   (id, name, script, timeout_sec, memory_max)
CHECKS = [
    ("01", "inventory",          "01_inventory.py",          600,  _limits.DEFAULT_MEMORY_MAX),
    ("02", "torch_abi",          "02_torch_abi.py",          1800, _limits.HEAVY_MEMORY_MAX),
    ("03", "attention_backend",  "03_attention_backend.py",  2400, _limits.HEAVY_MEMORY_MAX),
    ("04", "generation_sanity",  "04_generation_sanity.py",  2400, _limits.HEAVY_MEMORY_MAX),
    ("05", "vllm_serve",         "05_vllm_serve.py",         3600, _limits.HEAVY_MEMORY_MAX),
    ("06", "determinism",        "06_determinism.py",        5400, _limits.HEAVY_MEMORY_MAX),
    ("08", "sandbox_probe",      "08_sandbox_probe.py",      900,  _limits.DEFAULT_MEMORY_MAX),
    ("07", "lora_step_cost",     "07_lora_step_cost.py",     7200, _limits.HEAVY_MEMORY_MAX),
]

# Reporting order stays numeric regardless of execution order.
REPORT_ORDER = ["01", "02", "03", "04", "05", "06", "07", "08"]

# What Gate 0 actually requires. Check 06 is listed as "must report", not
# "must be byte-identical" -- that distinction is the whole point of the gate.
GATE_REQUIREMENTS = {
    "02": "device tensor ops succeed in fp32 and bf16",
    "04": "three non-corrupted generations on the sdpa path",
    "05": "at least one vLLM configuration reaches ready state and serves a completion",
    "06": "all four determinism cells reported with an explicit verdict",
    "07": "seconds per step and three epoch extrapolations, no OOM at the chosen config",
}


def run_one(cid, name, script, timeout, memory_max=None, only=None):
    if only and cid not in only:
        return None
    path = Path(__file__).resolve().parent / script
    log = C.LOG_DIR / f"{cid}_{name}.log"
    C.LOG_DIR.mkdir(parents=True, exist_ok=True)
    cmd, limit_info = _limits.wrap(
        [sys.executable, str(path)], memory_max=memory_max, tag=f"{cid}-{name}"
    )
    print(f"\n{'='*70}\nRUN {cid} {name}\n{'='*70}", flush=True)
    print(f"memory ceiling: {limit_info}", flush=True)
    t0 = time.time()
    with open(log, "w") as fh:
        fh.write(f"# memory ceiling: {json.dumps(limit_info)}\n# command: {' '.join(cmd)}\n\n")
        fh.flush()
        try:
            p = subprocess.run(
                cmd,
                stdout=fh,
                stderr=subprocess.STDOUT,
                timeout=timeout,
                cwd=str(C.REPO),
            )
            rc = p.returncode
        except subprocess.TimeoutExpired:
            rc = 124
            fh.write(f"\n\n!!! check timed out after {timeout}s\n")
    dur = round(time.time() - t0, 1)
    print(f"-> rc={rc} in {dur}s, log={log.relative_to(C.REPO)}", flush=True)

    res_path = C.CHECK_DIR / f"{cid}_{name}.json"
    if res_path.exists():
        result = json.loads(res_path.read_text())
    else:
        # The check died before it could write anything -- a segfault looks
        # exactly like this, so record it as a failure with the log tail.
        tail = ""
        try:
            tail = "\n".join(log.read_text(errors="replace").splitlines()[-40:])
        except Exception:
            pass
        oom = rc in (137, -9) or "Killed" in tail or "out of memory" in tail.lower()
        result = {
            "check_id": cid,
            "name": name,
            "status": C.STATUS_FAIL,
            "duration_sec": dur,
            "notes": [
                f"check produced no result file (rc={rc}); it crashed or was killed"
                + (
                    f" -- consistent with the {limit_info.get('memory_max')} memory ceiling "
                    "terminating it, which is the ceiling working as intended"
                    if oom and limit_info.get("applied")
                    else ""
                )
            ],
            "data": {"exit_code": rc, "log_tail": tail, "likely_oom_killed": oom},
        }
        C.CHECK_DIR.mkdir(parents=True, exist_ok=True)
        res_path.write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n")
    result["exit_code"] = rc
    result["runner_duration_sec"] = dur
    result["log"] = str(log.relative_to(C.REPO))
    result["memory_ceiling"] = limit_info
    # Persist the enriched record immediately. Nothing is held in memory until
    # the end -- a check that kills the host must not take the earlier results
    # with it.
    res_path.write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n")
    return result


def build_summary(results):
    by_id = {r["check_id"]: r for r in results}
    summary = {
        "gate": "P0",
        "model": C.MODEL_ID,
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "host": platform.node(),
        "checks": {
            r["check_id"]: {"name": r["name"], "status": r["status"], "duration_sec": r.get("runner_duration_sec")}
            for r in results
        },
    }

    reqs = {}
    for cid, desc in GATE_REQUIREMENTS.items():
        r = by_id.get(cid)
        reqs[cid] = {
            "requirement": desc,
            "status": (r or {}).get("status", "missing"),
            "met": bool(r and r["status"] in (C.STATUS_PASS, C.STATUS_WARN)),
        }
    # 06 is special: WARN (a cell that could not be measured but was explained)
    # still satisfies "reported with an explicit verdict".
    summary["gate_requirements"] = reqs
    summary["gate_passed"] = all(v["met"] for v in reqs.values())

    # Headline numbers other phases will quote.
    head = {}
    c1 = by_id.get("01", {}).get("data", {})
    if c1:
        head["gpu"] = c1.get("torch", {}).get("device_name")
        head["compute_capability"] = c1.get("torch", {}).get("compute_capability")
        head["torch"] = c1.get("torch", {}).get("version")
        head["cuda_runtime"] = c1.get("torch", {}).get("cuda_runtime_linked")
        head["free_disk_gib"] = c1.get("disk", {}).get("hf_cache", {}).get("free_gib")
    c2h = by_id.get("02", {}).get("data", {})
    if c2h:
        head["compat_mode"] = c2h.get("compat_mode")
        head["has_ptx"] = c2h.get("has_ptx")
        head["achieved_tflops_bf16"] = (c2h.get("throughput") or {}).get("achieved_tflops_bf16")
        head["first_matmul_sec"] = (c2h.get("first_call") or {}).get("first_matmul_sec")
    c5 = by_id.get("05", {}).get("data", {})
    if c5:
        head["vllm_default_config"] = (c5.get("project_default") or {}).get("name")
    c6 = by_id.get("06", {}).get("data", {})
    if c6:
        head["determinism_matrix"] = c6.get("summary_rows")
    c7 = by_id.get("07", {}).get("data", {})
    if c7 and c7.get("chosen"):
        ch = c7["chosen"]
        head["sec_per_optimizer_step"] = ch.get("sec_per_optimizer_step")
        head["tokens_per_second"] = ch.get("tokens_per_second")
        head["peak_allocated_gib"] = ch.get("peak_allocated_gib")
        head["lora_config"] = ch.get("config")
        head["epoch_hours"] = {k: v["hours"] for k, v in (ch.get("epoch_extrapolation") or {}).items()}
    summary["headline"] = head

    # The four known failure modes this gate exists to settle.
    #
    # A verdict is only written where the check that owns it actually ran and
    # produced the evidence for it. "The install succeeded" or "an adjacent
    # check passed" are not evidence, and where there is none the verdict is
    # "unknown" -- said out loud rather than inferred.
    c2 = by_id.get("02", {}).get("data", {})
    c3 = by_id.get("03", {}).get("data", {})
    fm = {}

    if "02" not in by_id:
        fm["cuda12_wheel_on_cuda13_runtime"] = {
            "verdict": "unknown",
            "reason": "check 02 did not run; nothing else can decide this",
            "evidence": {},
        }
    else:
        v = c2.get("failure_mode_1_verdict")
        fm["cuda12_wheel_on_cuda13_runtime"] = {
            "verdict": v or ("occurred" if by_id["02"]["status"] != C.STATUS_PASS else "unknown"),
            "occurred": (v == "occurred") if v else None,
            "evidence": {
                "torch": c2.get("torch_version"),
                "cuda_runtime_linked": c2.get("cuda_runtime_linked"),
                "driver": c2.get("driver_version"),
                "arch_list": c2.get("arch_list"),
                "device_sm": c2.get("device_sm"),
                "device_sm_in_arch_list": c2.get("device_sm_in_arch_list"),
                "ptx_entries": c2.get("ptx_entries"),
                "has_ptx": c2.get("has_ptx"),
                "compat_mode": c2.get("compat_mode"),
                "compat_explanation": c2.get("compat_explanation"),
                "numeric": [
                    {
                        "dtype": d.get("dtype"),
                        "ok": d.get("ok"),
                        "max_abs_err": d.get("max_abs_err"),
                        "max_rel_err": d.get("max_rel_err"),
                        "rel_tolerance": d.get("rel_tolerance"),
                        "error": d.get("error"),
                    }
                    for d in (c2.get("dtypes") or [])
                ],
                "first_call": c2.get("first_call"),
                "first_op_warnings": c2.get("first_op_warnings"),
                "throughput": c2.get("throughput"),
            },
        }

    if "03" not in by_id:
        fm["flash_attn_no_sm121_kernel"] = {
            "verdict": "unknown",
            "reason": "check 03 did not run",
            "evidence": {},
        }
    else:
        fa = (c3 or {}).get("flash_attention_2", {})
        v = c3.get("flash_attn_verdict")
        # An availability finding is not a kernel finding. Keep them apart.
        if v == "unavailable_no_wheel":
            occurred = None
            claim = (
                "flash_attention_2 is unusable here because no prebuilt wheel exists and "
                "this project does not compile on the training host. Whether its kernels "
                "would work on sm_121 was NOT tested -- no verdict on the kernel itself."
            )
        elif v in ("kernel_unsupported_on_sm121", "loads_but_output_corrupted"):
            occurred = True
            claim = "directly observed kernel-level failure on sm_121"
        elif v == "worked":
            occurred = False
            claim = "flash_attention_2 produced clean output on sm_121"
        else:
            occurred = None
            claim = "flash_attention_2 failed outside the expected classes"
        fm["flash_attn_no_sm121_kernel"] = {
            "verdict": v or "unknown",
            "occurred": occurred,
            "claim": claim,
            "evidence": {
                "installed": c3.get("flash_attn_installed"),
                "wheel_probe": c3.get("wheel_probe"),
                "failure_class": fa.get("failure_class"),
                "error": (fa.get("error_message") or "")[:800] or None,
                "corrupted": fa.get("corrupted"),
                "output_sample": (fa.get("output") or "")[:400] or None,
                "compiled_anything": c3.get("compiled_anything"),
                "source_build_incident": c3.get("source_build_incident"),
            },
        }

    if "05" not in by_id:
        fm["vllm_cuda_graph_capture_fails"] = {
            "verdict": "unknown",
            "reason": "check 05 did not run",
            "evidence": {},
        }
    else:
        attempts = {a["name"]: a for a in (c5.get("attempts") or [])}
        dflt = attempts.get("default") or {}
        eager = attempts.get("enforce_eager") or {}
        if dflt.get("ready") is None:
            verdict, occurred = "unknown", None
        elif dflt.get("ready"):
            verdict, occurred = "did_not_occur", False
        else:
            verdict, occurred = "occurred", True
        fm["vllm_cuda_graph_capture_fails"] = {
            "verdict": verdict,
            "occurred": occurred,
            "evidence": {
                "default_ready": dflt.get("ready"),
                "default_startup_result": dflt.get("startup_result"),
                "enforce_eager_ready": eager.get("ready"),
                "default_log_tail": (dflt.get("log_tail") or "")[-1500:] or None,
            },
        }

    if "06" not in by_id:
        fm["greedy_not_byte_reproducible_under_concurrency"] = {
            "verdict": "unknown",
            "reason": "check 06 did not run",
            "evidence": {},
        }
    else:
        rows = {(r["batch_invariant"], r["mode"]): r for r in (c6.get("summary_rows") or [])}
        conc_off = rows.get((False, "concurrent"), {})
        conc_on = rows.get((True, "concurrent"), {})
        if conc_off.get("samples"):
            occurred = conc_off.get("byte_identical") is False
            verdict = "occurred" if occurred else "did_not_occur"
        else:
            occurred, verdict = None, "unknown"
        fm["greedy_not_byte_reproducible_under_concurrency"] = {
            "verdict": verdict,
            "occurred": occurred,
            "reason": None if conc_off.get("samples") else conc_off.get("unmeasured_reason"),
            "evidence": {
                "concurrent_byte_identical_bi_off": conc_off.get("byte_identical"),
                "concurrent_byte_identical_bi_on": conc_on.get("byte_identical"),
                "concurrent_bi_on_unmeasured_reason": conc_on.get("unmeasured_reason"),
                "sequential_byte_identical_bi_off": rows.get((False, "sequential"), {}).get("byte_identical"),
                "throughput_cost": c6.get("batch_invariant_throughput_cost"),
            },
        }

    summary["known_failure_modes"] = fm
    return summary


def main():
    only = None
    args = [a for a in sys.argv[1:] if a != "--report-only"]
    report_only = "--report-only" in sys.argv[1:]
    if args:
        only = set(args)

    C.ENV_DIR.mkdir(parents=True, exist_ok=True)
    C.CHECK_DIR.mkdir(parents=True, exist_ok=True)

    if not report_only:
        for cid, name, script, timeout, memory_max in CHECKS:
            run_one(cid, name, script, timeout, memory_max, only)

    by_name = {cid: name for cid, name, _, _, _ in CHECKS}
    results = []
    for cid in REPORT_ORDER:
        name = by_name[cid]
        p = C.CHECK_DIR / f"{cid}_{name}.json"
        if p.exists():
            results.append(json.loads(p.read_text()))

    summary = build_summary(results)
    gate = {"summary": summary, "checks": {r["check_id"]: r for r in results}}

    lock = C.ENV_DIR / "versions.lock"
    gate["summary"]["versions_lock_present"] = lock.exists()

    out = C.ENV_DIR / "gate0.json"
    out.write_text(json.dumps(gate, indent=2, ensure_ascii=False) + "\n")
    print(f"\nwrote {out.relative_to(C.REPO)}")

    render_report.render(gate)
    print("wrote reports/env-report.md")
    render_determinism.render(gate)
    print("wrote docs/determinism.md")

    print("\n" + json.dumps(summary["gate_requirements"], indent=2, ensure_ascii=False))
    print(f"\nGATE 0 PASSED: {summary['gate_passed']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
