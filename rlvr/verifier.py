# -*- coding: utf-8 -*-
"""The reward. Two deterministic checks, in memory, nothing else.

No container, no compiler, no subprocess. The CVSS sandbox exists because CVSS
scoring needs the specification's own formula executed, and it scores tens of
thousands of items once. A reward loop runs 8 rollouts x 64 prompts per step;
a verifier that takes a second per item is 512 seconds of verification per
step and the run never finishes. So the sandbox stays in evaluation and the
reward stays in this process.

The two components are kept separate all the way to the log. A run where
schema reward saturates while exact-match reward stays flat is a different
outcome from both rising, and a scalar hides the difference.

The schema check is `eval/scorers/schema.py`, imported unmodified. The reward
has to be the same judgement the evaluation makes, or the demonstration
optimises one target and is measured against another.
"""

from __future__ import annotations

import json
from pathlib import Path

import jsonschema

REPO = Path(__file__).resolve().parents[1]
TASK = "cve_to_cwe"


class Verifier:
    def __init__(self, schema_path: Path | None = None):
        path = Path(schema_path) if schema_path else REPO / "datasets" / "schemas" / f"{TASK}.json"
        self.schema_path = path
        self.schema = json.loads(path.read_text())
        self.validator = jsonschema.Draft202012Validator(self.schema)
        # Imported, not reimplemented: normalization is one strip and at most
        # one markdown fence, and it must match what P4 scores.
        from eval.scorers import schema as p4_schema
        self._p4 = p4_schema

    def score(self, text: str, target: dict) -> dict:
        """-> {schema_valid, exact_match, normalization, value}. Both in {0, 1}."""
        s = self._p4.score_one(text, self.validator)
        ok_schema = 1.0 if s["schema_valid"] else 0.0
        ok_exact = 0.0
        if s["schema_valid"] and isinstance(s["value"], dict):
            ok_exact = 1.0 if s["value"].get("cwe_id") == target.get("cwe_id") else 0.0
        return {"schema_valid": ok_schema, "exact_match": ok_exact,
                "normalization": s.get("normalization"), "value": s.get("value")}

    def fingerprint(self) -> dict:
        import hashlib
        return {
            "task": TASK,
            "schema_path": str(self.schema_path.relative_to(REPO)),
            "schema_sha256": hashlib.sha256(self.schema_path.read_bytes()).hexdigest(),
            "scorer_path": "eval/scorers/schema.py",
            "scorer_sha256": hashlib.sha256(
                (REPO / "eval" / "scorers" / "schema.py").read_bytes()).hexdigest(),
            "components": ["schema_valid", "exact_match"],
            "range_per_component": [0.0, 1.0],
            "in_process": True,
            "subprocess_used": False,
        }
