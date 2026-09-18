"""Check 04 -- greedy generation sanity on the sdpa path.

Three prompts (English, Korean, JSON-output instruction), 128 greedy tokens each.
Heuristics flag obvious corruption; the raw text is written to the log because
the heuristics do not get the final say -- a human reads the output.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import _common as C  # noqa: E402

CHECK_ID = "04"
CHECK_NAME = "generation_sanity"

MAX_NEW_TOKENS = 128

PROMPTS = [
    {
        "id": "en_prose",
        "lang": "en",
        "text": "Explain in a short paragraph why input validation matters in web applications.",
    },
    {
        "id": "ko_prose",
        "lang": "ko",
        "text": "SQL 인젝션 취약점이 무엇인지 한국어로 간단히 설명해 주세요.",
    },
    {
        "id": "json_schema",
        "lang": "en",
        "text": (
            "Return ONLY a JSON object, no prose, with exactly these keys: "
            '"cwe_id" (string), "severity" (one of low/medium/high/critical), '
            '"summary" (string). Describe a stack-based buffer overflow.'
        ),
    },
]


def run():
    import torch
    from transformers import AutoModelForCausalLM, AutoTokenizer

    notes = []
    data = {"model": C.MODEL_ID, "attn_implementation": "sdpa", "max_new_tokens": MAX_NEW_TOKENS}

    tok = AutoTokenizer.from_pretrained(C.MODEL_ID)
    try:
        model = AutoModelForCausalLM.from_pretrained(
            C.MODEL_ID, dtype=torch.bfloat16, attn_implementation="sdpa", device_map="cuda"
        )
    except TypeError:
        model = AutoModelForCausalLM.from_pretrained(
            C.MODEL_ID, torch_dtype=torch.bfloat16, attn_implementation="sdpa", device_map="cuda"
        )
    model.eval()

    results = []
    for p in PROMPTS:
        text = tok.apply_chat_template(
            [{"role": "user", "content": p["text"]}], tokenize=False, add_generation_prompt=True
        )
        ids = tok(text, return_tensors="pt").to("cuda")
        with torch.no_grad():
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
        m = C.corruption_metrics(completion)
        corrupted, why = C.looks_corrupted(completion, m)
        entry = {
            "id": p["id"],
            "lang": p["lang"],
            "prompt": p["text"],
            "output": completion,
            "new_tokens": int(gen.shape[1] - ids["input_ids"].shape[1]),
            "metrics": m,
            "corrupted": corrupted,
            "corruption_reason": why,
        }
        if p["id"] == "json_schema":
            body = completion.strip()
            if body.startswith("```"):
                body = body.split("```")[1]
                body = body[4:] if body.lower().startswith("json") else body
            try:
                parsed = json.loads(body.strip())
                entry["json_parsed"] = True
                entry["json_keys"] = sorted(parsed.keys()) if isinstance(parsed, dict) else None
            except Exception as exc:
                entry["json_parsed"] = False
                entry["json_error"] = repr(exc)
        results.append(entry)

        print(f"\n--- {p['id']} ({p['lang']}) ---")
        print(f"prompt: {p['text']}")
        print(f"metrics: {m} corrupted={corrupted} {why}")
        print("OUTPUT >>>")
        print(completion)
        print("<<< END OUTPUT")

    data["generations"] = results
    clean = [r for r in results if not r["corrupted"]]
    data["clean_count"] = len(clean)
    data["total_count"] = len(results)

    if len(clean) != len(results):
        notes.append(
            "corrupted generations: "
            + ", ".join(r["id"] for r in results if r["corrupted"])
        )
    js = next((r for r in results if r["id"] == "json_schema"), None)
    if js is not None:
        notes.append(
            f"JSON-output prompt parsed as valid JSON: {js.get('json_parsed')}"
            + (f" keys={js.get('json_keys')}" if js.get("json_parsed") else "")
        )
    notes.append(
        "heuristics are a tripwire, not a verdict -- full raw outputs are in "
        "logs/04_generation_sanity.log for human review"
    )

    return {
        "status": C.STATUS_PASS if len(clean) == len(results) else C.STATUS_FAIL,
        "data": data,
        "notes": notes,
    }


if __name__ == "__main__":
    sys.exit(C.main(sys.modules[__name__]))
