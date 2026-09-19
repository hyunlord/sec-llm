"""Decision 1 -- temporal split.

Evaluation is drawn only from CVEs published on or after CUTOFF. Random
splitting cannot protect against pretraining contamination for CVE text, which
is mirrored across the web; a date the base model cannot have seen can.

Qwen2.5-7B-Instruct was released in September 2024 with a training cutoff that
is not precisely documented, so the cutoff carries a margin past the release
date. Training uses only records published BEFORE the cutoff -- the conservative
reading of "split by time", and the one that also simulates deployment (predict
CVEs that did not exist yet). Post-cutoff records that are not sampled into
evaluation are held back entirely and counted, not folded into training.

A pre-cutoff evaluation set of the same size is held out from 2022-2023. The
score gap between the two is the pipeline's own estimate of contamination
magnitude and is reported as a first-class result.
"""

from __future__ import annotations

from datasets.common import stable_int

CUTOFF = "2025-01-01"
PRE_EVAL_YEARS = (2022, 2023)
EVAL_SAMPLE = 5000          # CVEs sampled per temporal eval set, before per-task filtering
EVAL_SEED = "sec-llm-p3-eval-v1"

# Per-entity split labels. One label per CVE, used by every CVE task, so no CVE
# can land in two splits -- verified in code by build.py, not assumed here.
TRAIN = "train"
EVAL_POST = "eval_post_cutoff"
EVAL_PRE = "eval_pre_cutoff"
POST_UNUSED = "post_cutoff_unused"     # eligible for eval, not sampled; never trained on
EXCLUDED = "excluded"                  # not PUBLISHED / not kept / no date


def period(date_published: str | None, year: int | None) -> str:
    if not date_published:
        return "no_date"
    if date_published >= CUTOFF:
        return "post_cutoff"
    if year in PRE_EVAL_YEARS:
        return "pre_eval_window"
    return "pre_cutoff_other"


def assign_splits(rows: list[dict]) -> dict[str, str]:
    """rows: cve_table rows. Returns {cve_id: split}. Deterministic.

    Sampling is by sorted stable hash of the CVE id under a fixed seed, so the
    same input rows always yield the same evaluation sets regardless of the
    order the rows arrived in.
    """
    eligible = [r for r in rows if r.get("state") == "PUBLISHED" and r.get("dedup_keep") and r.get("date_published")]
    post = sorted((r["cve_id"] for r in eligible if period(r["date_published"], r["year"]) == "post_cutoff"),
                  key=lambda c: (stable_int(EVAL_SEED + c, 1 << 62), c))
    pre = sorted((r["cve_id"] for r in eligible if period(r["date_published"], r["year"]) == "pre_eval_window"),
                 key=lambda c: (stable_int(EVAL_SEED + c, 1 << 62), c))

    split: dict[str, str] = {}
    for r in rows:
        split[r["cve_id"]] = EXCLUDED
    n = min(EVAL_SAMPLE, len(post), len(pre))
    for c in post[:n]:
        split[c] = EVAL_POST
    for c in post[n:]:
        split[c] = POST_UNUSED
    for c in pre[:n]:
        split[c] = EVAL_PRE
    for r in eligible:
        if split[r["cve_id"]] == EXCLUDED:
            split[r["cve_id"]] = TRAIN
    return split


def assign_attack_splits(rows: list[dict]) -> dict[str, str]:
    """Same rule for techniques, keyed on STIX `created`. Small numbers; all
    post-cutoff techniques go to evaluation and an equal count is held out
    from 2022-2023."""
    eligible = [r for r in rows if r.get("dedup_keep") and r.get("created")]
    post = sorted((r["technique_id"] for r in eligible if r["created"] >= CUTOFF),
                  key=lambda t: (stable_int(EVAL_SEED + t, 1 << 62), t))
    pre = sorted((r["technique_id"] for r in eligible if r["year"] in PRE_EVAL_YEARS),
                 key=lambda t: (stable_int(EVAL_SEED + t, 1 << 62), t))
    n = min(len(post), len(pre))
    split = {r["technique_id"]: EXCLUDED for r in rows}
    for t in post[:n]:
        split[t] = EVAL_POST
    for t in post[n:]:
        split[t] = POST_UNUSED
    for t in pre[:n]:
        split[t] = EVAL_PRE
    for r in eligible:
        if split[r["technique_id"]] == EXCLUDED:
            split[r["technique_id"]] = TRAIN
    return split
