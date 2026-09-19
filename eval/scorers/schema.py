"""Axis 1 -- schema validity. Mechanical: jsonschema, nothing else.

Scored separately from accuracy on purpose. An output that does not parse is not
a wrong answer, it is a different failure, and collapsing the two hides whether a
condition lost formatting or lost knowledge. Accuracy is therefore computed over
schema-valid outputs only, and both denominators are reported.

Normalization before parsing is deliberately minimal and fully declared:

  1. strip surrounding whitespace
  2. strip ONE surrounding markdown code fence (```json ... ``` or ``` ... ```)

Nothing else. No extracting a JSON object from surrounding prose, no repairing
quotes, no trailing-comma tolerance. A model that wraps its answer in a fence has
followed the format in substance; a model that buries it in a paragraph has not.
"""

from __future__ import annotations

import json
from pathlib import Path

import jsonschema

RAW, FENCE = "raw", "fence_stripped"
NORMALIZATIONS = (RAW, FENCE)


def normalize(text: str) -> tuple[str, str]:
    s = (text or "").strip()
    if s.startswith("```"):
        body = s[3:]
        if body[:4].lower() == "json":
            body = body[4:]
        end = body.rfind("```")
        if end != -1:
            return body[:end].strip(), FENCE
    return s, RAW


def load_validators(schema_dir: Path, tasks) -> dict:
    out = {}
    for t in tasks:
        schema = json.loads((schema_dir / f"{t}.json").read_text())
        out[t] = (schema, jsonschema.Draft202012Validator(schema))
    return out


def score_one(text: str, validator) -> dict:
    cand, norm = normalize(text)
    try:
        parsed = json.loads(cand)
    except Exception as e:
        return {"parsed": False, "schema_valid": False, "normalization": norm,
                "error": f"{type(e).__name__}", "value": None}
    errors = sorted(validator.iter_errors(parsed), key=str)
    return {"parsed": True, "schema_valid": not errors, "normalization": norm,
            "error": (errors[0].message[:200] if errors else None),
            "value": parsed if not errors else None,
            "parsed_value": parsed}


def rate(rows, key) -> dict:
    n = len(rows)
    k = sum(1 for r in rows if r[key])
    return {"n": n, "k": k, "rate": (k / n if n else 0.0)}
