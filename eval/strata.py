"""Contamination strata: zero / low / high.

P3.2 attached `train_ngram_coverage` (the fraction of an evaluation item's
13-grams that appear anywhere in training) to every evaluation item and recorded
quartile boundaries per set. Those quartiles are NOT used here. Coverage is
zero-inflated -- 72.8% of cve_to_cwe/eval_post_cutoff is exactly 0, so q25 and
q50 are both 0.0 and q2 is empty by construction -- which makes quartile strata
incomparable across sets.

Three strata instead, defined from each set's own distribution:

  zero : coverage == 0                     shares no 13-gram with training
  low  : 0 < coverage <= median(positive)  
  high : coverage > median(positive)

The split point is the median of the positive values, a location read off the
data, not a level anyone chose. It is recorded per set in the run manifest so
every stratified number can be recomputed.
"""

from __future__ import annotations

ZERO, LOW, HIGH = "zero", "low", "high"
STRATA = (ZERO, LOW, HIGH)
FIELD = "train_ngram_coverage"


def positive_median(values) -> float:
    """Nearest-rank median over the strictly positive values, the same convention
    datasets/lengths.py uses for percentiles."""
    v = sorted(x for x in values if x > 0)
    if not v:
        return 0.0
    return v[min(len(v) - 1, int(round(0.5 * (len(v) - 1))))]


def stratum(coverage: float, pos_median: float) -> str:
    if coverage == 0:
        return ZERO
    return LOW if coverage <= pos_median else HIGH


def for_items(items) -> dict:
    """items: iterable of dicts carrying FIELD. Returns the split point, the
    per-item assignment and the counts."""
    covs = [float(i[FIELD]) for i in items]
    med = positive_median(covs)
    by_id = {i["example_id"]: stratum(float(i[FIELD]), med) for i in items}
    counts = {s: sum(1 for v in by_id.values() if v == s) for s in STRATA}
    return {
        "positive_median": med,
        "n": len(covs),
        "counts": counts,
        "by_id": by_id,
        "definition": "zero: coverage==0; low: 0<coverage<=median(positive); high: coverage>median(positive)",
        "field": FIELD,
        "note": ("recorded quartiles are deliberately not used: coverage is zero-inflated and quartile "
                 "boundaries collapse, which makes quartile strata incomparable across evaluation sets"),
    }
