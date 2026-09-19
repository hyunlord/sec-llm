"""Axis 3 -- general ability, the forgetting check. MMLU subset and HellaSwag.

Fixed subsets, chosen by stable hash of the item's own content so the selection
does not depend on row order, the dataset's internal shuffling, or the machine.
The subset is hashed and the hash is recorded in the run manifest; a later run
that selects different items is detectable rather than silently different.

Protocol, and its limitation, stated plainly. The canonical MMLU/HellaSwag
protocol compares the log-likelihood of each continuation. This harness instead
presents the choices as lettered options and reads the letter the model
generates. That is mechanical and reproducible, and it is the same interface the
domain tasks use, but it is NOT the canonical protocol and the absolute numbers
are not comparable to published leaderboard scores. They are comparable BETWEEN
conditions in this project, which is the only comparison P5 needs. Recorded in
reports/eval_harness.md under what this harness cannot measure.

Letter extraction is reported separately from accuracy, the same way schema
validity is separated from task accuracy: a model that answers in prose has a
formatting failure, not a knowledge failure.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from eval.common import HarnessError, sha256_text, stable_int

SUBSET_N = 1000
LETTERS = ("A", "B", "C", "D")
PINS_FILE = Path(__file__).resolve().parents[1] / "general_pins.json"

SPECS = {
    "mmlu": {"repo": "cais/mmlu", "config": "all", "split": "test"},
    "hellaswag": {"repo": "Rowan/hellaswag", "config": None, "split": "validation"},
}

TEMPLATE = ("The following is a multiple choice question. Answer with the letter of the "
            "correct option and nothing else.\n\n{stem}\n\nA. {a}\nB. {b}\nC. {c}\nD. {d}\n\nAnswer:")
TEMPLATE_SHA = sha256_text(TEMPLATE)
_LETTER_RE = re.compile(r"\b([ABCD])\b")


def _pins() -> dict:
    return json.loads(PINS_FILE.read_text()) if PINS_FILE.exists() else {}


def _resolve_revision(name: str, allow_network: bool) -> str:
    """Pin to an immutable dataset commit. Once recorded, the recorded value is
    authoritative and a drifting upstream cannot change the subset silently."""
    pins = _pins()
    if name in pins:
        return pins[name]["revision"]
    if not allow_network:
        raise HarnessError(f"{name} is not pinned in {PINS_FILE.name} and network resolution is disabled")
    from huggingface_hub import HfApi
    info = HfApi().dataset_info(SPECS[name]["repo"])
    rev = info.sha
    pins[name] = {"repo": SPECS[name]["repo"], "revision": rev,
                  "config": SPECS[name]["config"], "split": SPECS[name]["split"]}
    PINS_FILE.write_text(json.dumps(pins, indent=2, sort_keys=True) + "\n")
    return rev


def prepare(name: str, n: int = SUBSET_N, allow_network: bool = True) -> dict:
    """Return {'items': [...], 'pin': {...}} with items already rendered."""
    import datasets as hfds
    spec = SPECS[name]
    rev = _resolve_revision(name, allow_network)
    ds = hfds.load_dataset(spec["repo"], spec["config"], split=spec["split"], revision=rev)
    rows = []
    for r in ds:
        if name == "mmlu":
            stem, choices, gold = r["question"], list(r["choices"]), int(r["answer"])
            extra = {"subject": r.get("subject")}
        else:
            stem = f"{r['activity_label']}: {r['ctx']}"
            choices, gold = list(r["endings"]), int(r["label"])
            extra = {"source_id": r.get("source_id")}
        if len(choices) != 4 or not (0 <= gold < 4):
            continue
        key = sha256_text("|".join([stem] + [str(c) for c in choices]))
        rows.append({"key": key, "stem": stem, "choices": choices, "gold": LETTERS[gold], "extra": extra})
    rows.sort(key=lambda x: (stable_int(x["key"], 1 << 62), x["key"]))
    pick = sorted(rows[:n], key=lambda x: x["key"])
    items = []
    for r in pick:
        c = r["choices"]
        prompt = TEMPLATE.format(stem=r["stem"], a=c[0], b=c[1], c=c[2], d=c[3])
        items.append({
            "example_id": f"{name}:{r['key'][:16]}",
            "task": name, "split": spec["split"], "prompt": prompt,
            "target": {"answer": r["gold"]}, "meta": r["extra"],
        })
    return {
        "items": items,
        "pin": {"repo": spec["repo"], "revision": rev, "config": spec["config"], "split": spec["split"],
                "pool_size": len(rows), "subset_n": len(items),
                "subset_sha256": sha256_text("\n".join(i["example_id"] for i in items)),
                "prompt_template_sha256": TEMPLATE_SHA,
                "selection": "stable sha256 of (stem + choices), smallest n, independent of row order",
                "protocol": "letter generation, not log-likelihood comparison; see reports/eval_harness.md"},
    }


def score_one(text: str, target: dict) -> dict:
    s = (text or "").strip()
    m = _LETTER_RE.search(s.upper()) or re.match(r"\s*([ABCD])", s.upper())
    got = m.group(1) if m else None
    return {"extracted": got is not None, "prediction": got, "target": target["answer"],
            "correct": bool(got is not None and got == target["answer"])}
