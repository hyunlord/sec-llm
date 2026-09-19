"""Axis 2a -- exact match for the two single-label tasks.

cve_to_cwe: one CWE id. attack_technique: one ATT&CK technique id. Both are
identifiers, so the only normalization is strip + upper-case; nothing is mapped,
no near-miss is credited, and a parent/child CWE relation is NOT partial credit
(P3's CWE policy already refused to treat a parent/child disagreement as
agreement, and the scorer must not undo that decision).

attack_technique is `scored: false` in the dataset manifest: 738 training
examples and 79 evaluation items per split give confidence intervals wider than
+/-10 points. It is scored here so the number exists, and every report marks it
unscored and keeps it out of comparisons between conditions.
"""

from __future__ import annotations

FIELDS = {"cve_to_cwe": "cwe_id", "attack_technique": "technique_id"}


def norm_id(v) -> str | None:
    if not isinstance(v, str):
        return None
    return v.strip().upper() or None


def score_one(task: str, predicted: dict | None, target: dict) -> dict:
    field = FIELDS[task]
    want = norm_id(target.get(field))
    got = norm_id((predicted or {}).get(field))
    return {"field": field, "target": want, "prediction": got,
            "correct": bool(want is not None and got == want)}
