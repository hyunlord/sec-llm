"""Qwen2.5 tokenizer loaded from the pinned files. No weights, no network."""

from __future__ import annotations

import functools
import json

from datasets.common import REPO


@functools.lru_cache(maxsize=1)
def tokenizer():
    from tokenizers import Tokenizer

    lock = json.loads((REPO / "ingest" / "sources.lock.json").read_text())
    pin = lock["sources"]["tokenizer_qwen25"]
    path = REPO / "data" / "raw" / "tokenizer_qwen25" / pin["commit_sha"][:12] / "tokenizer.json"
    return Tokenizer.from_file(str(path))


def n_tokens(text: str) -> int:
    return len(tokenizer().encode(text, add_special_tokens=False).ids)
