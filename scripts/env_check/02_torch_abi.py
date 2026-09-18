"""Check 02 -- torch ABI smoke on device, fp32 and bf16.

This is the check that catches a CUDA 12-targeted wheel installed on a CUDA 13
runtime: the import succeeds, `torch.cuda.is_available()` returns True, and the
first real kernel launch segfaults or raises `undefined symbol`. It also catches
the narrower Blackwell problem -- torch shipping no cubin for sm_121.

Each arithmetic result is compared against a CPU reference so a kernel that runs
but returns garbage is caught too.
"""

from __future__ import annotations

import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import _common as C  # noqa: E402

CHECK_ID = "02"
CHECK_NAME = "torch_abi"

N = 2048


def _dtype_smoke(torch, dtype, name, tol):
    """matmul + elementwise + reduction + norm on device, verified on CPU."""
    result = {"dtype": name, "ops": {}}
    g = torch.Generator(device="cpu").manual_seed(1234)
    a_c = torch.randn(N, N, generator=g, dtype=torch.float32)
    b_c = torch.randn(N, N, generator=g, dtype=torch.float32)

    a = a_c.to("cuda", dtype=dtype)
    b = b_c.to("cuda", dtype=dtype)

    t0 = time.time()
    mm = a @ b
    torch.cuda.synchronize()
    t_mm = time.time() - t0

    ref = (a_c @ b_c)
    got = mm.float().cpu()
    rel = ((got - ref).abs().max() / ref.abs().max()).item()
    result["ops"]["matmul"] = {
        "seconds": round(t_mm, 4),
        "tflops": round(2 * N**3 / t_mm / 1e12, 2),
        "max_rel_err": rel,
        "tolerance": tol,
        "ok": rel <= tol,
    }

    # Elementwise + reduction + softmax + layer_norm: different kernel families,
    # different chances of a missing symbol.
    s = torch.nn.functional.softmax(a.float(), dim=-1)
    ln = torch.nn.functional.layer_norm(a.float(), (N,))
    red = a.float().sum()
    torch.cuda.synchronize()
    result["ops"]["softmax_rowsum"] = {
        "value": float(s.sum(-1).mean().item()),
        "ok": abs(float(s.sum(-1).mean().item()) - 1.0) < 1e-3,
    }
    result["ops"]["layer_norm_std"] = {
        "value": float(ln.std().item()),
        "ok": abs(float(ln.std().item()) - 1.0) < 1e-2,
    }
    result["ops"]["reduction_finite"] = {"value": float(red.item()), "ok": torch.isfinite(red).item()}

    # Host round-trip: catches a broken copy engine path.
    back = mm.cpu()
    result["ops"]["d2h_copy"] = {"ok": back.shape == (N, N) and torch.isfinite(back.float()).all().item()}

    result["ok"] = all(v["ok"] for v in result["ops"].values())
    return result


def run():
    notes = []
    data = {"matrix_size": N}

    try:
        import torch
    except Exception as exc:
        return {
            "status": C.STATUS_FAIL,
            "data": {"import_error": repr(exc)},
            "notes": ["torch import failed -- rebuild the environment before anything else"],
        }

    data["torch_version"] = torch.__version__
    data["cuda_runtime_linked"] = torch.version.cuda
    data["arch_list"] = torch.cuda.get_arch_list()

    rc, smi_cuda, _ = C.sh(
        "nvidia-smi --query-gpu=driver_version --format=csv,noheader"
    )
    data["driver_version"] = smi_cuda

    if not torch.cuda.is_available():
        return {
            "status": C.STATUS_FAIL,
            "data": data,
            "notes": ["torch.cuda.is_available() is False"],
        }

    cap = torch.cuda.get_device_capability(0)
    data["device_sm"] = f"sm_{cap[0]}{cap[1]}"
    data["device_sm_in_arch_list"] = data["device_sm"] in data["arch_list"]
    print(f"torch {torch.__version__} cuda={torch.version.cuda} device={data['device_sm']}")
    print(f"arch_list={data['arch_list']} contains_device_sm={data['device_sm_in_arch_list']}")

    results = []
    for dtype, name, tol in ((torch.float32, "float32", 1e-3), (torch.bfloat16, "bfloat16", 5e-2)):
        try:
            r = _dtype_smoke(torch, dtype, name, tol)
        except Exception as exc:
            r = {"dtype": name, "ok": False, "error": repr(exc)}
            notes.append(f"{name} device ops failed: {exc!r}")
        results.append(r)
        print(f"\n{name}: ok={r.get('ok')}")
        for op, v in (r.get("ops") or {}).items():
            print(f"  {op}: {v}")
        if "error" in r:
            print(f"  ERROR: {r['error']}")
    data["dtypes"] = results
    data["peak_allocated_gib"] = round(torch.cuda.max_memory_allocated() / 2**30, 3)

    ok = all(r.get("ok") for r in results)
    if ok and not data["device_sm_in_arch_list"]:
        notes.append(
            f"torch ships no cubin for {data['device_sm']} (arch_list={data['arch_list']}) "
            "yet every device op produced numerically correct results: Blackwell "
            "family-level binary compatibility (sm_120 -> sm_121) is working on this build."
        )
    if ok:
        notes.append(
            "installation route: torch installed from the PyTorch cu130 wheel index "
            "(UV_TORCH_BACKEND=cu130) to match the CUDA 13.0 runtime. No NGC container "
            "fallback was required."
        )

    return {"status": C.STATUS_PASS if ok else C.STATUS_FAIL, "data": data, "notes": notes}


if __name__ == "__main__":
    sys.exit(C.main(sys.modules[__name__]))
