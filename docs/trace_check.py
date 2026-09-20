# -*- coding: utf-8 -*-
"""Traceability check: no number in a published document without a source.

Two independent assertions, in this order:

A. **Every recorded number re-resolves.** `docs/trace.json` holds
   `{kind, args}` for each published figure, not a pre-rendered string. This
   check re-resolves each path against the file on disk and re-renders it with
   the same function the builder used. A figure that was typed by hand, or a
   manifest that changed after the document was written, fails here.

B. **Every numeric literal in a document is one of those numbers.** The
   documents are re-read, code spans and link targets are removed (a command,
   a hash, an issue URL is not a published figure), and every remaining digit
   run must appear in the registry. A number nobody registered fails here --
   which is what catches a figure typed straight into prose.

Run: `python -m docs.trace_check --assert-all`
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))

from docs.common import (DOCS, RENDERERS, Resolver, TraceError,  # noqa: E402
                         strip_exempt, tokens)

CHECKED = [
    "README.md",
    "docs/MODEL_CARD.md",
    "docs/DATASET.md",
    "docs/LICENSES.md",
    "docs/SBOM.md",
    "docs/REPRODUCE.md",
]


def load_trace() -> dict:
    path = DOCS / "trace.json"
    if not path.exists():
        raise SystemExit("docs/trace.json is missing -- run `make docs` first")
    return json.loads(path.read_text())


def check_resolution(trace: dict, R: Resolver) -> tuple[dict, list]:
    """A: re-resolve and re-render every recorded figure. Returns token index."""
    failures = []
    index = {}
    for i, e in enumerate(trace["entries"]):
        kind = e["kind"]
        if kind not in RENDERERS:
            failures.append(f"entry {i}: unknown renderer {kind!r}")
            continue
        try:
            text = RENDERERS[kind](R, e["args"])
        except TraceError as exc:
            failures.append(f"entry {i} ({kind}): {exc}")
            continue
        if text != e["text"]:
            failures.append(
                f"entry {i} ({kind}, {e['args']}): document says {e['text']!r}, "
                f"source now renders {text!r}")
            continue
        for t in tokens(text):
            index.setdefault(t, []).append(i)
    return index, failures


def check_documents(index: dict, trace: dict) -> tuple[int, list]:
    """B: every numeric literal in prose must be a registered figure."""
    failures = []
    total = 0
    for rel in CHECKED:
        path = REPO / rel
        if not path.exists():
            failures.append(f"{rel}: missing -- run `make docs`")
            continue
        body = strip_exempt(path.read_text(encoding="utf-8"))
        for lineno, line in enumerate(body.splitlines(), 1):
            for tok in tokens(line):
                total += 1
                if tok not in index:
                    failures.append(
                        f"{rel}:{lineno}: untraceable number {tok!r} -- "
                        f"not registered by any renderer. Read it from a manifest "
                        f"or leave it out.")
    return total, failures


def describe(trace: dict, entry_ids) -> str:
    out = []
    for i in entry_ids[:3]:
        e = trace["entries"][i]
        a = e["args"]
        ref = a.get("ref") or a.get("rate_ref") or (a.get("refs") or [[]])[0]
        out.append(f"{'.'.join(str(x) for x in ref)}")
    return "; ".join(out)


def main(argv) -> int:
    assert_all = "--assert-all" in argv
    trace = load_trace()
    R = Resolver()

    index, fail_a = check_resolution(trace, R)
    total, fail_b = check_documents(index, trace)

    print(f"A. recorded figures re-resolved: {len(trace['entries']):,} entries, "
          f"{len(fail_a):,} failures")
    print(f"B. numeric literals in {len(CHECKED)} documents: {total:,} checked, "
          f"{len(fail_b):,} untraceable")

    if "--show" in argv:
        for tok in sorted(index, key=lambda t: -len(index[t]))[:15]:
            print(f"   {tok:>14}  x{len(index[tok]):<4} {describe(trace, index[tok])}")

    failures = fail_a + fail_b
    if failures:
        print()
        for f in failures[:60]:
            print("FAIL " + f)
        if len(failures) > 60:
            print(f"... and {len(failures) - 60} more")
        if assert_all:
            return 1
        return 1
    print("TRACE OK: every published number resolves to a committed source")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
