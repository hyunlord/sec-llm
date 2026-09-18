"""Check 03 -- sdpa vs flash_attention_2 on this GPU.

flash-attn 2.x ships no kernel for Blackwell sm_121. The point of this check is
not to discover that flash attention is the better backend -- sdpa is the project
default regardless -- but to record verbatim *how* it fails here, so nobody
re-litigates the decision later.
"""

from __future__ import annotations

import gc
import sys
import traceback
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import _common as C  # noqa: E402

CHECK_ID = "03"
CHECK_NAME = "attention_backend"

PROMPT = "List three common categories of software vulnerability, one per line."
MAX_NEW_TOKENS = 48


def _load(model_id, impl, torch):
    from transformers import AutoModelForCausalLM

    kwargs = dict(attn_implementation=impl, device_map="cuda")
    try:
        return AutoModelForCausalLM.from_pretrained(model_id, dtype=torch.bfloat16, **kwargs)
    except TypeError:
        # transformers < 5 spells it torch_dtype
        return AutoModelForCausalLM.from_pretrained(model_id, torch_dtype=torch.bfloat16, **kwargs)


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
    except Exception as exc:
        out["loaded"] = out.get("loaded", False)
        out["generated"] = False
        out["output"] = None
        out["error"] = repr(exc)
        out["traceback"] = traceback.format_exc()
        out["corrupted"] = None
    finally:
        del model
        gc.collect()
        try:
            torch.cuda.empty_cache()
        except Exception:
            pass
    return out


def run():
    import torch
    from transformers import AutoTokenizer

    notes = []
    data = {"model": C.MODEL_ID, "prompt": PROMPT, "max_new_tokens": MAX_NEW_TOKENS}

    try:
        import flash_attn  # noqa: F401

        data["flash_attn_installed"] = True
        data["flash_attn_version"] = getattr(
            __import__("flash_attn"), "__version__", "unknown"
        )
    except Exception as exc:
        data["flash_attn_installed"] = False
        data["flash_attn_import_error"] = repr(exc)

    build_log = C.REPO / "logs" / "install_flash_attn.log"
    if build_log.exists():
        tail = build_log.read_text(errors="replace").splitlines()[-40:]
        data["flash_attn_build_log_tail"] = "\n".join(tail)

    tok = AutoTokenizer.from_pretrained(C.MODEL_ID)

    for impl in ("sdpa", "flash_attention_2"):
        print(f"\n--- attn_implementation={impl} ---")
        r = _attempt(C.MODEL_ID, impl, tok, torch)
        data[impl] = r
        if r["error"]:
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
    if fa.get("error"):
        notes.append(
            "flash_attention_2 is unusable on this machine -- it raised: "
            + (fa["error"] or "")[:400]
        )
    elif fa.get("corrupted"):
        notes.append(
            "flash_attention_2 loaded and generated but the output is corrupted: "
            + (fa.get("corruption_reason") or "")
        )
    else:
        notes.append(
            "flash_attention_2 unexpectedly produced clean output on sm_121. The project "
            "still defaults to sdpa: an unvalidated kernel path on an unsupported arch is "
            "not worth the risk for a correctness-sensitive training run."
        )
    notes.append("project default for training and HF inference: attn_implementation='sdpa'")

    return {
        "status": C.STATUS_PASS if sdpa_ok else C.STATUS_FAIL,
        "data": data,
        "notes": notes,
    }


if __name__ == "__main__":
    sys.exit(C.main(sys.modules[__name__]))
