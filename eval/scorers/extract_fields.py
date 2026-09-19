"""Axis 2c -- structured_extract: field-level precision and recall.

Four fields with different shapes, so they are scored differently and reported
separately. Averaging them into one number would hide that `versions` is a set
and `impact` is frequently absent.

  vendor, product : single string. exact match after strip + casefold.
  versions        : set of strings. micro precision/recall over the set, so an
                    item predicting 3 of 5 versions with no spurious entry scores
                    precision 1.0 / recall 0.6 rather than 'wrong'.
  impact          : nullable. Per datasets/CARD.md, scored ONLY where the target
                    is non-null; predicting a value where the target is null is
                    counted as a false positive and reported, not silently
                    ignored, but it does not move the accuracy denominator.

Precision here is over items that predicted a value; recall is over items whose
target has one. Both denominators are reported with every number.
"""

from __future__ import annotations

SINGLE = ("vendor", "product")
ALL_FIELDS = ("vendor", "product", "versions", "impact")


def cf(v) -> str | None:
    return v.strip().casefold() if isinstance(v, str) and v.strip() else None


def version_set(v) -> set:
    if not isinstance(v, list):
        return set()
    return {x.strip().casefold() for x in v if isinstance(x, str) and x.strip()}


def score_one(predicted: dict | None, target: dict) -> dict:
    p = predicted or {}
    out = {}
    for f in SINGLE:
        want, got = cf(target.get(f)), cf(p.get(f))
        out[f] = {"has_target": want is not None, "has_prediction": got is not None,
                  "correct": bool(want is not None and got == want)}
    tv, pv = version_set(target.get("versions")), version_set(p.get("versions"))
    tp = len(tv & pv)
    out["versions"] = {"tp": tp, "fp": len(pv - tv), "fn": len(tv - pv),
                       "n_target": len(tv), "n_prediction": len(pv),
                       "exact_set": bool(tv == pv and tv)}
    iw, ig = cf(target.get("impact")), cf(p.get("impact"))
    out["impact"] = {"has_target": iw is not None, "has_prediction": ig is not None,
                     "correct": bool(iw is not None and ig == iw),
                     "spurious": bool(iw is None and ig is not None)}
    return out


def aggregate(rows) -> dict:
    """Micro precision/recall per field over a list of score_one results."""
    agg = {}
    for f in SINGLE + ("impact",):
        have_t = [r for r in rows if r[f]["has_target"]]
        have_p = [r for r in rows if r[f]["has_prediction"]]
        correct = sum(1 for r in rows if r[f]["correct"])
        agg[f] = {
            "n_with_target": len(have_t), "n_with_prediction": len(have_p), "correct": correct,
            "precision": (correct / len(have_p) if have_p else 0.0),
            "recall": (correct / len(have_t) if have_t else 0.0),
        }
        if f == "impact":
            agg[f]["spurious_when_target_null"] = sum(1 for r in rows if r[f]["spurious"])
    tp = sum(r["versions"]["tp"] for r in rows)
    fp = sum(r["versions"]["fp"] for r in rows)
    fn = sum(r["versions"]["fn"] for r in rows)
    agg["versions"] = {
        "tp": tp, "fp": fp, "fn": fn,
        "precision": (tp / (tp + fp) if tp + fp else 0.0),
        "recall": (tp / (tp + fn) if tp + fn else 0.0),
        "exact_set_rate": (sum(1 for r in rows if r["versions"]["exact_set"]) / len(rows) if rows else 0.0),
        "n_items": len(rows),
    }
    for f, a in agg.items():
        p, r = a["precision"], a["recall"]
        a["f1"] = (2 * p * r / (p + r) if p + r else 0.0)
    return agg


def item_all_fields_correct(row: dict, target: dict) -> bool:
    """One strict per-item number, for the paired condition comparison: every
    field that has a target is exactly right and the version set matches."""
    ok = all(row[f]["correct"] for f in SINGLE)
    ok = ok and row["versions"]["fp"] == 0 and row["versions"]["fn"] == 0
    if target.get("impact") is not None:
        ok = ok and row["impact"]["correct"]
    return bool(ok)
