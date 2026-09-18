"""Check 02 -- torch ABI smoke on device, fp32 and bf16.

This is the check that decides failure mode (1). Its signature is a clean
install followed by a crash, wrong numbers, or a silent JIT fallback on the
first device op -- so installation having succeeded proves nothing, and the
verdict is not written anywhere but here.

On this machine there is a second question layered on top. torch ships cubins
for sm_80/90/100/110/120 but the GB10 is sm_121, so either:

  * get_arch_list() contains a compute_* (PTX) entry, in which case the driver
    JIT-compiles at first launch -- correct results, slow first call; or
  * it does not, in which case the stack is leaning on CUDA 13 family-level
    binary compatibility (sm_120 cubins loaded onto an sm_121 part), which is a
    weaker and much less documented guarantee.

Which of those two it is changes what we have to re-verify on every torch bump,
so the check reports it explicitly rather than inferring it.
"""

from __future__ import annotations

import contextlib
import os
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import _common as C  # noqa: E402

CHECK_ID = "02"
CHECK_NAME = "torch_abi"

# Correctness matrix size. Large enough that tiling/split-k strategies engage,
# small enough that the fp64 CPU reference finishes in seconds.
N = 4096

# Throughput matrix size and iteration count for the steady-state measurement.
PERF_N = 8192
PERF_ITERS = 20
PERF_WARMUP = 5

# GB10 dense BF16 peak, derived from NVIDIA's headline "1 PFLOP" figure, which
# is quoted at FP4 *with sparsity*: 1000 (FP4 sparse) / 2 (sparsity) / 2 (FP4
# -> FP8) / 2 (FP8 -> BF16) ~= 125 TFLOPS dense BF16. This is a derived number,
# not a datasheet quote, so it is recorded as a reference point for spotting a
# generic-kernel fallback -- not as a pass/fail threshold.
GB10_BF16_DENSE_TFLOPS_REF = 125.0
SHORTFALL_WARN_RATIO = 0.25  # below 25% of reference suggests a generic path

JIT_PATTERNS = [
    "no kernel image",
    "ptx",
    "jit",
    "cubin",
    "not compiled",
    "invalid device function",
    "unsupported gpu architecture",
]


@contextlib.contextmanager
def capture_fd_stderr():
    """Capture C-level stderr (fd 2), not just Python's sys.stderr.

    'no kernel image is available' and PTX JIT diagnostics are emitted by the
    CUDA runtime below Python, so redirecting sys.stderr would miss them.
    """
    saved = os.dup(2)
    tmp = tempfile.TemporaryFile(mode="w+b")
    try:
        sys.stderr.flush()
        os.dup2(tmp.fileno(), 2)
        yield tmp
    finally:
        sys.stderr.flush()
        os.dup2(saved, 2)
        os.close(saved)


def _scan_warnings(text):
    hits = []
    for line in (text or "").splitlines():
        low = line.lower()
        if any(p in low for p in JIT_PATTERNS):
            hits.append(line.rstrip())
    return hits


def _first_call_latency(torch):
    """Time context creation and the very first kernel launch separately.

    A PTX JIT fallback shows up as a large first-matmul time that does not
    repeat on the second call.
    """
    out = {}
    t0 = time.perf_counter()
    torch.cuda.init()
    torch.cuda.synchronize()
    out["context_init_sec"] = round(time.perf_counter() - t0, 4)

    a = torch.ones(256, 256, device="cuda", dtype=torch.float32)
    torch.cuda.synchronize()

    t0 = time.perf_counter()
    _ = a @ a
    torch.cuda.synchronize()
    out["first_matmul_sec"] = round(time.perf_counter() - t0, 4)

    t0 = time.perf_counter()
    _ = a @ a
    torch.cuda.synchronize()
    out["second_matmul_sec"] = round(time.perf_counter() - t0, 6)

    fm, sm = out["first_matmul_sec"], out["second_matmul_sec"]
    out["first_call_overhead_x"] = round(fm / sm, 1) if sm > 0 else None
    # A JIT compile is hundreds of milliseconds, not microseconds.
    out["suggests_jit_compile"] = fm > 0.25
    return out


def _numeric_smoke(torch, dtype, name, rel_tol, abs_tol):
    """Device matmul vs an fp64 CPU reference. Correctness, not just survival."""
    result = {"dtype": name, "rel_tolerance": rel_tol, "abs_tolerance": abs_tol}
    g = torch.Generator(device="cpu").manual_seed(1234)
    a64 = torch.randn(N, N, generator=g, dtype=torch.float64)
    b64 = torch.randn(N, N, generator=g, dtype=torch.float64)

    t0 = time.perf_counter()
    ref = a64 @ b64  # fp64 CPU reference
    result["cpu_reference_sec"] = round(time.perf_counter() - t0, 3)

    a = a64.to("cuda", dtype=dtype)
    b = b64.to("cuda", dtype=dtype)
    torch.cuda.synchronize()

    t0 = time.perf_counter()
    got = a @ b
    torch.cuda.synchronize()
    result["device_matmul_sec"] = round(time.perf_counter() - t0, 4)

    got64 = got.double().cpu()
    diff = (got64 - ref).abs()
    max_abs = diff.max().item()
    denom = ref.abs().max().item()
    max_rel = max_abs / denom if denom else float("inf")

    result["max_abs_err"] = max_abs
    result["max_rel_err"] = max_rel
    result["reference_max_magnitude"] = denom
    result["all_finite"] = bool(torch.isfinite(got64).all().item())
    result["ok"] = result["all_finite"] and max_rel <= rel_tol

    # A few other kernel families -- a missing symbol rarely hits only GEMM.
    s = torch.nn.functional.softmax(a.float(), dim=-1)
    ln = torch.nn.functional.layer_norm(a.float(), (N,))
    red = a.float().sum()
    torch.cuda.synchronize()
    aux = {
        "softmax_rowsum_err": abs(float(s.sum(-1).mean().item()) - 1.0),
        "layer_norm_std": float(ln.std().item()),
        "reduction_finite": bool(torch.isfinite(red).item()),
        "d2h_roundtrip_ok": bool(got.cpu().shape == (N, N)),
    }
    aux["ok"] = (
        aux["softmax_rowsum_err"] < 1e-3
        and abs(aux["layer_norm_std"] - 1.0) < 1e-2
        and aux["reduction_finite"]
        and aux["d2h_roundtrip_ok"]
    )
    result["aux_ops"] = aux
    result["ok"] = result["ok"] and aux["ok"]
    return result


def _throughput(torch):
    """Steady-state bf16 GEMM throughput. A big shortfall means a generic path."""
    a = torch.randn(PERF_N, PERF_N, device="cuda", dtype=torch.bfloat16)
    b = torch.randn(PERF_N, PERF_N, device="cuda", dtype=torch.bfloat16)
    for _ in range(PERF_WARMUP):
        _ = a @ b
    torch.cuda.synchronize()

    t0 = time.perf_counter()
    for _ in range(PERF_ITERS):
        _ = a @ b
    torch.cuda.synchronize()
    elapsed = time.perf_counter() - t0

    per_iter = elapsed / PERF_ITERS
    flops = 2 * PERF_N**3
    tflops = flops / per_iter / 1e12
    ratio = tflops / GB10_BF16_DENSE_TFLOPS_REF
    return {
        "matrix_size": PERF_N,
        "iterations": PERF_ITERS,
        "warmup": PERF_WARMUP,
        "sec_per_matmul": round(per_iter, 5),
        "achieved_tflops_bf16": round(tflops, 2),
        "reference_tflops_bf16_dense": GB10_BF16_DENSE_TFLOPS_REF,
        "reference_basis": (
            "derived from NVIDIA's headline 1 PFLOP FP4-with-sparsity figure "
            "(1000 / 2 sparsity / 2 FP4->FP8 / 2 FP8->BF16); a reference point "
            "for spotting a generic-kernel fallback, not a datasheet quote"
        ),
        "fraction_of_reference": round(ratio, 3),
        "large_shortfall": ratio < SHORTFALL_WARN_RATIO,
        "shortfall_threshold": SHORTFALL_WARN_RATIO,
    }


def run():
    notes = []
    data = {"correctness_matrix_size": N}

    try:
        import torch
    except Exception as exc:
        return {
            "status": C.STATUS_FAIL,
            "data": {"import_error": repr(exc)},
            "notes": [
                "torch import failed -- failure mode (1) verdict: OCCURRED at import time. "
                "Rebuild the environment from the cu130 wheel index or an NGC aarch64 "
                "container before anything else; do not patch around it with package pins."
            ],
        }

    data["torch_version"] = torch.__version__
    data["cuda_runtime_linked"] = torch.version.cuda
    arch_list = torch.cuda.get_arch_list()
    data["arch_list"] = arch_list

    _, driver, _ = C.sh("nvidia-smi --query-gpu=driver_version --format=csv,noheader")
    data["driver_version"] = driver

    if not torch.cuda.is_available():
        return {
            "status": C.STATUS_FAIL,
            "data": data,
            "notes": ["torch.cuda.is_available() is False -- failure mode (1) verdict: OCCURRED"],
        }

    cap = torch.cuda.get_device_capability(0)
    device_sm = f"sm_{cap[0]}{cap[1]}"
    data["device_sm"] = device_sm
    data["device_name"] = torch.cuda.get_device_name(0)
    data["device_sm_in_arch_list"] = device_sm in arch_list

    # --- PTX verdict -------------------------------------------------------
    ptx_entries = [a for a in arch_list if a.startswith("compute_")]
    data["ptx_entries"] = ptx_entries
    data["has_ptx"] = bool(ptx_entries)
    if data["device_sm_in_arch_list"]:
        data["compat_mode"] = "native_cubin"
        compat_text = f"torch ships a native cubin for {device_sm}"
    elif data["has_ptx"]:
        data["compat_mode"] = "ptx_jit"
        compat_text = (
            f"no cubin for {device_sm}, but PTX is present ({ptx_entries}) -- the driver "
            "JIT-compiles at first launch: correct results, slow first call"
        )
    else:
        data["compat_mode"] = "family_binary_compat"
        compat_text = (
            f"no cubin for {device_sm} and no PTX entry in arch_list -- the stack is "
            "relying on CUDA 13 Blackwell family-level binary compatibility "
            "(sm_120 cubins loaded onto an sm_121 part)"
        )
    data["compat_explanation"] = compat_text
    print(f"torch {torch.__version__} cuda={torch.version.cuda} driver={driver}")
    print(f"device {data['device_name']} {device_sm}")
    print(f"arch_list={arch_list}")
    print(f"PTX entries: {ptx_entries or 'NONE'}")
    print(f"compat mode: {data['compat_mode']} -- {compat_text}")

    # --- first-call latency + stderr capture on the very first device op ---
    print("\n--- first device op (stderr captured at fd level) ---")
    with capture_fd_stderr() as tmp:
        try:
            data["first_call"] = _first_call_latency(torch)
            first_err = None
        except Exception as exc:
            data["first_call"] = {"error": repr(exc)}
            first_err = repr(exc)
        tmp.flush()
        tmp.seek(0)
        captured = tmp.read().decode("utf-8", errors="replace")
    data["first_op_stderr"] = captured.strip() or None
    data["first_op_warnings"] = _scan_warnings(captured)
    print(f"first_call: {data['first_call']}")
    if data["first_op_stderr"]:
        print("captured stderr during first device op:")
        print(data["first_op_stderr"][:4000])
    if data["first_op_warnings"]:
        print(f"!! kernel/PTX warnings: {data['first_op_warnings']}")
    if first_err:
        return {
            "status": C.STATUS_FAIL,
            "data": data,
            "notes": [
                f"first device op raised: {first_err}",
                "failure mode (1) verdict: OCCURRED -- clean install, crash on first device op",
            ],
        }

    # --- numeric correctness against an fp64 CPU reference -----------------
    print(f"\n--- numeric correctness, {N}x{N}, device vs fp64 CPU reference ---")
    results = []
    for dtype, name, rel_tol, abs_tol in (
        (torch.float32, "float32", 1e-4, 1e-2),
        (torch.bfloat16, "bfloat16", 5e-2, 5.0),
    ):
        try:
            r = _numeric_smoke(torch, dtype, name, rel_tol, abs_tol)
        except Exception as exc:
            r = {"dtype": name, "ok": False, "error": repr(exc)}
            notes.append(f"{name} device ops failed: {exc!r}")
        results.append(r)
        if "error" in r:
            print(f"{name}: ERROR {r['error']}")
        else:
            print(
                f"{name}: ok={r['ok']} max_abs_err={r['max_abs_err']:.4g} "
                f"max_rel_err={r['max_rel_err']:.4g} (rel tol {r['rel_tolerance']}) "
                f"device {r['device_matmul_sec']}s / cpu-fp64 ref {r['cpu_reference_sec']}s"
            )
            print(f"  aux ops: {r['aux_ops']}")
    data["dtypes"] = results

    # --- steady-state throughput ------------------------------------------
    print(f"\n--- steady-state bf16 throughput, {PERF_N}x{PERF_N} x{PERF_ITERS} ---")
    try:
        data["throughput"] = _throughput(torch)
        t = data["throughput"]
        print(
            f"{t['achieved_tflops_bf16']} TFLOPS bf16 "
            f"({t['fraction_of_reference']:.1%} of the {t['reference_tflops_bf16_dense']} "
            f"TFLOPS reference), {t['sec_per_matmul']}s per matmul"
        )
    except Exception as exc:
        data["throughput"] = {"error": repr(exc)}
        notes.append(f"throughput measurement failed: {exc!r}")

    data["peak_allocated_gib"] = round(torch.cuda.max_memory_allocated() / 2**30, 3)

    ok = all(r.get("ok") for r in results)

    # --- the verdict this check exists to write ----------------------------
    if ok:
        data["failure_mode_1_verdict"] = "did_not_occur"
        notes.append(
            "failure mode (1) verdict: DID NOT OCCUR. Device ops in fp32 and bf16 both "
            f"ran and matched an fp64 CPU reference within tolerance on {device_sm}."
        )
    else:
        data["failure_mode_1_verdict"] = "occurred"
        notes.append(
            "failure mode (1) verdict: OCCURRED. Device ops ran but did not produce "
            "correct results -- see data.dtypes for the errors against the fp64 reference."
        )

    notes.append(f"architecture compatibility: {data['compat_mode']} -- {compat_text}")
    if data["compat_mode"] == "family_binary_compat" and ok:
        notes.append(
            "no PTX fallback exists in this build, so every torch/CUDA upgrade must re-run "
            "check 02 before it is trusted -- family-level binary compatibility is not a "
            "guarantee the way a native cubin or a PTX entry is."
        )
    if data.get("first_call", {}).get("suggests_jit_compile"):
        notes.append(
            f"first kernel launch took {data['first_call']['first_matmul_sec']}s vs "
            f"{data['first_call']['second_matmul_sec']}s for the second "
            f"({data['first_call']['first_call_overhead_x']}x) -- consistent with a PTX JIT compile"
        )
    if data["first_op_warnings"]:
        notes.append("CUDA emitted kernel/PTX diagnostics on the first device op: "
                     + " | ".join(data["first_op_warnings"][:5]))
    t = data.get("throughput") or {}
    if t.get("achieved_tflops_bf16"):
        notes.append(
            f"achieved bf16 GEMM throughput {t['achieved_tflops_bf16']} TFLOPS, "
            f"{t['fraction_of_reference']:.1%} of the derived {t['reference_tflops_bf16_dense']} "
            "TFLOPS reference"
            + (" -- large shortfall, kernel selection may be falling back to a generic path"
               if t.get("large_shortfall") else "")
        )
    notes.append(
        "installation route: torch from the PyTorch cu130 wheel index "
        "(UV_TORCH_BACKEND=cu130), matching the CUDA 13.0 runtime. No NGC container "
        "fallback and no source build were used."
    )

    status = C.STATUS_PASS if ok else C.STATUS_FAIL
    if ok and t.get("large_shortfall"):
        status = C.STATUS_WARN
    return {"status": status, "data": data, "notes": notes}


if __name__ == "__main__":
    sys.exit(C.main(sys.modules[__name__]))
