"""Axis 2b -- CVSS v3.1: per-field accuracy, whole-vector exact match, base score.

Three different things are reported rather than one number:

  per-field      each of the eight base metrics separately, because a model that
                 gets attackVector right and scope wrong is not 'half correct' in
                 any useful sense -- scope changes the privilege weights and the
                 whole score
  whole vector   all eight metrics right AND the vector string equal: the only
                 result that would be usable downstream
  base score     numeric equality at one decimal, which is what CVSS defines

The base score is also recomputed from the model's own vector string by the
sandbox axis (eval/sandbox.py) inside a container, which is a stronger check: it
verifies the model's vector is internally consistent with the score it claims.
"""

from __future__ import annotations

METRICS = ("attackVector", "attackComplexity", "privilegesRequired", "userInteraction",
           "scope", "confidentialityImpact", "integrityImpact", "availabilityImpact")


def norm_enum(v) -> str | None:
    return v.strip().upper() if isinstance(v, str) and v.strip() else None


def norm_vector(v) -> str | None:
    return v.strip().upper().replace(" ", "") if isinstance(v, str) and v.strip() else None


def norm_score(v):
    try:
        return round(float(v), 1)
    except (TypeError, ValueError):
        return None


def score_one(predicted: dict | None, target: dict) -> dict:
    p = predicted or {}
    fields = {}
    for m in METRICS:
        want, got = norm_enum(target.get(m)), norm_enum(p.get(m))
        fields[m] = {"target": want, "prediction": got, "correct": bool(want and got == want)}
    vw, vg = norm_vector(target.get("vectorString")), norm_vector(p.get("vectorString"))
    sw, sg = norm_score(target.get("baseScore")), norm_score(p.get("baseScore"))
    metrics_all = all(fields[m]["correct"] for m in METRICS)
    return {
        "fields": fields,
        "metrics_all_correct": metrics_all,
        "vector_string": {"target": vw, "prediction": vg, "correct": bool(vw and vg == vw)},
        "base_score": {"target": sw, "prediction": sg, "correct": bool(sw is not None and sg == sw)},
        "whole_vector_exact": bool(metrics_all and vw and vg == vw),
    }
