"""Decision 3 -- the general-instruction replay set.

OpenAssistant/oasst2, Apache-2.0, human-written. License was read from the
dataset card before download; the pin is a Hugging Face commit SHA in
ingest/sources.lock.json; the raw file was fetched through the P1 downloader so
it carries a digest sidecar and reproduces offline.

Only human-written, reviewed, top-ranked assistant replies to a human prompt are
used. oasst2 flags model-generated messages with `synthetic: true` and names the
model; those are excluded so the replay set's provenance stays entirely human
and no third model's terms of use enter the picture.

The P2 secret/PII policy is applied verbatim: emails, internal hostnames and
private IPs become stable pseudonyms; anything in the secret category is
replaced with the unrecoverable marker; counts only are reported.
"""

from __future__ import annotations

import gzip
import json
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from datasets.common import REPO, stable_int  # noqa: E402
from process.canonical import canonicalize  # noqa: E402
from process.secrets import redact, scan_text  # noqa: E402

LANGS = ("en", "ko")
REPLAY_FRACTION_OF_TOTAL = 0.20   # replay tokens / (domain + replay) tokens
SEED = "sec-llm-p3-replay-v1"


def _pin() -> dict:
    lock = json.loads((REPO / "ingest" / "sources.lock.json").read_text())
    return lock["sources"]["replay_oasst2"]


def load_pairs() -> tuple[list[dict], dict]:
    pin = _pin()
    f = next(x for x in pin["files"] if x["path"].endswith(".jsonl.gz"))
    path = REPO / "data" / "raw" / "replay_oasst2" / pin["commit_sha"][:12] / f["path"]
    stats = Counter()
    msgs: dict[str, dict] = {}
    with gzip.open(path, "rt", encoding="utf-8") as fh:
        for line in fh:
            m = json.loads(line)
            msgs[m["message_id"]] = m
            stats["messages"] += 1

    pairs = []
    for m in msgs.values():
        if m.get("role") != "assistant":
            continue
        stats["assistant_messages"] += 1
        if m.get("deleted"):
            stats["skip_deleted"] += 1; continue
        if m.get("review_result") is False:
            stats["skip_failed_review"] += 1; continue
        if m.get("synthetic"):
            stats["skip_synthetic_model_generated"] += 1; continue
        # Rank is a quality ordering among sibling replies, not a provenance or
        # licence boundary. With top-ranked replies only, the pool reached 5.7% of
        # training tokens against a 20% target, so all reviewed human replies are
        # used and the rank is carried in the example for anyone who wants to
        # filter later.
        stats[f"rank_{m.get('rank')}"] += 1
        if m.get("lang") not in LANGS:
            stats["skip_language"] += 1; continue
        parent = msgs.get(m.get("parent_id") or "")
        if not parent or parent.get("role") != "prompter":
            stats["skip_no_prompter_parent"] += 1; continue
        if parent.get("synthetic") or parent.get("deleted"):
            stats["skip_parent_synthetic_or_deleted"] += 1; continue
        prompt, _ = canonicalize(parent.get("text") or "")
        reply, _ = canonicalize(m.get("text") or "")
        if len(prompt) < 8 or len(reply) < 8:
            stats["skip_too_short"] += 1; continue
        pairs.append({
            "replay_id": f"oasst2:{m['message_id']}",
            "lang": m.get("lang"),
            "rank": m.get("rank"),
            "prompt": prompt,
            "response": reply,
        })
        stats["pairs"] += 1
    pairs.sort(key=lambda p: p["replay_id"])
    return pairs, dict(stats)


def scan_and_redact(pairs: list[dict]) -> tuple[list[dict], dict]:
    """Apply the P2 policy. Returns redacted pairs and counts (never values)."""
    by_type = Counter()
    by_cat = Counter()
    touched = 0
    out = []
    for p in pairs:
        f = scan_text(p["prompt"]) + scan_text(p["response"])
        if f:
            touched += 1
            for x in f:
                by_type[x["type"]] += 1
                by_cat[x["category"]] += 1
        out.append({**p, "prompt": redact(p["prompt"]), "response": redact(p["response"])})
    return out, {
        "pairs_scanned": len(pairs),
        "pairs_with_findings": touched,
        "findings_by_type": dict(by_type),
        "findings_by_category": dict(by_cat),
        "policy": "identical to P2: secrets -> unrecoverable marker; PII -> stable pseudonym; counts only",
    }


def sample_to_budget(pairs: list[dict], token_len, domain_train_tokens: int) -> tuple[list[dict], dict]:
    """Take pairs in stable-hash order until replay tokens reach the budget.

    budget = domain * f/(1-f) so that replay is f of the total.
    """
    f = REPLAY_FRACTION_OF_TOTAL
    budget = int(domain_train_tokens * f / (1 - f))
    order = sorted(pairs, key=lambda p: (stable_int(SEED + p["replay_id"], 1 << 62), p["replay_id"]))
    chosen, used = [], 0
    for p in order:
        n = token_len(p["prompt"]) + token_len(p["response"])
        if used + n > budget and chosen:
            break
        chosen.append({**p, "n_tokens": n})
        used += n
    chosen.sort(key=lambda p: p["replay_id"])
    return chosen, {
        "domain_train_tokens": domain_train_tokens,
        "replay_token_budget": budget,
        "replay_tokens_used": used,
        "replay_fraction_of_total": round(used / (domain_train_tokens + used), 4) if used else 0.0,
        "pairs_available": len(pairs),
        "pairs_selected": len(chosen),
        "budget_exhausted_pool": len(chosen) == len(pairs),
    }
