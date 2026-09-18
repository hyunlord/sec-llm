"""Check 03 -- sdpa vs flash_attention_2 on this GPU.

This check compiles nothing. It answers three questions and stops:

  1. What does transformers actually do when asked for flash_attention_2 here?
  2. Does a prebuilt flash-attn wheel exist for this platform at all? (resolved
     dry-run only -- no download, no build)
  3. What happened when a source build was attempted on this host?

(3) is in scope because it is evidence about the platform rather than a mishap:
on a unified-memory part, a parallel host-side compile competes with the GPU for
the same physical pool. See docs/hardware-notes.md.

sdpa is the project default regardless of what any of this finds. The check
documents the reason; it does not make the decision.
"""

from __future__ import annotations

import gc
import json
import sys
import traceback
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import _common as C  # noqa: E402

CHECK_ID = "03"
CHECK_NAME = "attention_backend"

PROMPT = "List three common categories of software vulnerability, one per line."
MAX_NEW_TOKENS = 48

# The recorded incident. Kept as data so the report renders it verbatim and it
# does not depend on anyone remembering the session it came from.
BUILD_INCIDENT = {
    "date": "2026-09-18",
    "what": (
        "A flash-attn source build (flash-attn==2.8.3.post1, MAX_JOBS=16, "
        "--no-build-isolation) was started on the DGX Spark while the gate was "
        "being prepared."
    ),
    "outcome": (
        "The parallel nvcc jobs exhausted the shared 128 GiB unified memory pool. "
        "The host stopped responding to SSH and ICMP within roughly two minutes, "
        "stayed down for over an hour, and required a physical power cycle. No "
        "check result survived."
    ),
    "why_it_matters": (
        "On Grace-Blackwell the GPU and the host share one physical memory pool, "
        "so a host-side compile is not isolated from GPU work the way it is on a "
        "discrete-GPU x86 server. A CUDA allocator ceiling does not help, because "
        "the compiler never allocates through CUDA."
    ),
    "rule_adopted": (
        "No source compilation on the training host. Wheels only. If a package has "
        "no wheel for this platform, the absence is the finding."
    ),
}


def _load(model_id, impl, torch):
    from transformers import AutoModelForCausalLM

    kwargs = dict(attn_implementation=impl, device_map="cuda")
    try:
        return AutoModelForCausalLM.from_pretrained(model_id, dtype=torch.bfloat16, **kwargs)
    except TypeError:
        return AutoModelForCausalLM.from_pretrained(model_id, torch_dtype=torch.bfloat16, **kwargs)


def _classify_failure(err_text):
    """Distinguish 'not installed' from a genuine kernel-level failure.

    The two have very different meanings: the first says nothing about sm_121,
    the second is a direct observation about it.
    """
    low = (err_text or "").lower()
    if any(k in low for k in ("no module named 'flash_attn'", "flash_attn", "flash-attn")) and any(
        k in low for k in ("install", "not found", "no module", "requires", "importerror")
    ):
        return "not_installed"
    if any(k in low for k in ("no kernel image", "invalid device function", "unsupported", "sm_", "arch")):
        return "kernel_unsupported"
    if not err_text:
        return "none"
    return "other"


def _attempt(model_id, impl, tok, torch):
    out = {"attn_implementation": impl}
    model = None
    try:
        model = _load(model_id, impl, torch)
        out["loaded"] = True
        out["resolved_impl"] = str(getattr(model.config, "_attn_implementation", "unknown"))
        msgs = [{"role": "user", "content": PROMPT}]
        text = tok.apply_chat_template(msgs, tokenize=False, add_generation_prompt=True)
        ids = tok(text, return_tensors="pt").to("cuda")
        gen = model.generate(
            **ids,
            max_new_tokens=MAX_NEW_TOKENS,
            do_sample=False,
            temperature=None,
            top_p=None,
            top_k=None,
            pad_token_id=tok.pad_token_id or tok.eos_token_id,
        )
        completion = tok.decode(gen[0][ids["input_ids"].shape[1]:], skip_special_tokens=True)
        out["generated"] = True
        out["output"] = completion
        m = C.corruption_metrics(completion)
        out["metrics"] = m
        corrupted, why = C.looks_corrupted(completion, m)
        out["corrupted"] = corrupted
        out["corruption_reason"] = why
        out["error"] = None
        out["failure_class"] = "none"
    except Exception as exc:
        out["loaded"] = out.get("loaded", False)
        out["generated"] = False
        out["output"] = None
        out["error"] = repr(exc)
        out["error_message"] = str(exc)
        out["traceback"] = traceback.format_exc()
        out["corrupted"] = None
        out["failure_class"] = _classify_failure(str(exc) + " " + repr(exc))
    finally:
        del model
        gc.collect()
        try:
            torch.cuda.empty_cache()
        except Exception:
            pass
    return out


def _wheel_availability():
    """Resolve-only probe: does a prebuilt flash-attn wheel exist for this platform?

    `uv pip install --dry-run --only-binary=:all:` resolves against the index and
    reports what it *would* do. It downloads nothing and builds nothing; the
    --only-binary flag makes an sdist-only package a hard resolution failure,
    which is exactly the answer we want.
    """
    probe = {
        "method": "uv pip install --dry-run --only-binary=:all: flash-attn",
        "downloaded": False,
        "built": False,
    }
    rc, out, err = C.sh(
        f"uv pip install --python {sys.executable} --dry-run --only-binary=:all: flash-attn",
        timeout=180,
    )
    probe["returncode"] = rc
    probe["stdout"] = (out or "")[:3000]
    probe["stderr"] = (err or "")[:3000]
    combined = f"{out}\n{err}"
    if rc == 0:
        probe["wheel_available"] = True
        probe["verdict"] = "a prebuilt wheel resolves for this platform"
    else:
        probe["wheel_available"] = False
        low = combined.lower()
        if "no solution" in low or "only-binary" in low or "source distribution" in low or "sdist" in low:
            probe["verdict"] = (
                "no prebuilt wheel for this platform (aarch64 / CUDA 13 / "
                f"cp{sys.version_info.major}{sys.version_info.minor} / sm_121); "
                "the index offers source distributions only"
            )
        else:
            probe["verdict"] = "resolution failed; see resolver output"
    return probe


def run():
    import torch
    from transformers import AutoTokenizer

    notes = []
    data = {
        "model": C.MODEL_ID,
        "prompt": PROMPT,
        "max_new_tokens": MAX_NEW_TOKENS,
        "compiled_anything": False,
        "source_build_incident": BUILD_INCIDENT,
    }

    # Is it importable right now? (It should not be -- nothing installs it.)
    try:
        import flash_attn

        data["flash_attn_installed"] = True
        data["flash_attn_version"] = getattr(flash_attn, "__version__", "unknown")
    except Exception as exc:
        data["flash_attn_installed"] = False
        data["flash_attn_import_error"] = repr(exc)
    print(f"flash_attn importable: {data['flash_attn_installed']}")

    print("\n--- prebuilt wheel availability (resolve-only, no download, no build) ---")
    data["wheel_probe"] = _wheel_availability()
    print(f"rc={data['wheel_probe']['returncode']} -> {data['wheel_probe']['verdict']}")
    print(data["wheel_probe"]["stderr"][:1500] or data["wheel_probe"]["stdout"][:1500])

    tok = AutoTokenizer.from_pretrained(C.MODEL_ID)

    for impl in ("sdpa", "flash_attention_2"):
        print(f"\n--- attn_implementation={impl} ---")
        r = _attempt(C.MODEL_ID, impl, tok, torch)
        data[impl] = r
        if r["error"]:
            print(f"failure_class={r['failure_class']}")
            print(f"ERROR: {r['error']}")
            print(r.get("traceback", "")[-2000:])
        else:
            print(f"resolved: {r.get('resolved_impl')}")
            print(f"corrupted={r['corrupted']} metrics={r['metrics']}")
            print("OUTPUT >>>")
            print(r["output"])
            print("<<< END OUTPUT")

    sdpa_ok = bool(data["sdpa"].get("generated")) and data["sdpa"].get("corrupted") is False
    fa = data["flash_attention_2"]

    # The verdict, stated in terms of what was actually observed.
    if fa.get("failure_class") == "not_installed":
        data["flash_attn_verdict"] = "unavailable_no_wheel"
        notes.append(
            "flash_attention_2 is unavailable on this platform because no prebuilt wheel "
            "exists for it, and this project does not build CUDA extensions on the training "
            "host. transformers raised: " + (fa.get("error_message") or "")[:300]
        )
        notes.append(
            "note the limit of this evidence: this is an availability finding, not a direct "
            "observation of sm_121 kernel behaviour. Whether flash-attn 2.x would produce "
            "correct output on sm_121 was NOT tested and no verdict is claimed."
        )
    elif fa.get("failure_class") == "kernel_unsupported":
        data["flash_attn_verdict"] = "kernel_unsupported_on_sm121"
        notes.append(
            "flash_attention_2 loaded but failed at the kernel level on sm_121: "
            + (fa.get("error_message") or "")[:400]
        )
    elif fa.get("corrupted"):
        data["flash_attn_verdict"] = "loads_but_output_corrupted"
        notes.append(
            "flash_attention_2 ran but produced corrupted output: "
            + (fa.get("corruption_reason") or "")
        )
    elif fa.get("generated"):
        data["flash_attn_verdict"] = "worked"
        notes.append(
            "flash_attention_2 produced clean output on sm_121. The project still defaults to "
            "sdpa: an unvalidated kernel path on an architecture its authors do not target is "
            "not worth the risk in a correctness-sensitive training run."
        )
    else:
        data["flash_attn_verdict"] = "failed_other"
        notes.append("flash_attention_2 failed for a reason outside the expected classes: "
                     + (fa.get("error_message") or "")[:300])

    notes.append(f"prebuilt wheel probe: {data['wheel_probe']['verdict']}")
    notes.append("project default for training and HF inference: attn_implementation='sdpa'")
    notes.append(
        "this check compiled nothing. A source build was attempted once on "
        f"{BUILD_INCIDENT['date']} and took the host down; see docs/hardware-notes.md."
    )

    return {
        "status": C.STATUS_PASS if sdpa_ok else C.STATUS_FAIL,
        "data": data,
        "notes": notes,
    }


if __name__ == "__main__":
    sys.exit(C.main(sys.modules[__name__]))
