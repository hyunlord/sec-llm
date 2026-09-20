# -*- coding: utf-8 -*-
"""`make docs` -- regenerate every published document from manifests.

Three things happen here and nothing else:

1. Every run manifest that feeds a published number is checked with the same
   function the scorers use. A run whose manifest lacks a required setting is
   not scored, and by the same rule it is not published.
2. Each renderer is called with one shared formatter, so `docs/trace.json` ends
   up holding every number in every document with the path it was read from.
3. The files are written. Nothing here reads the clock: the output is a pure
   function of the files on disk, which is what makes a second `make docs`
   byte-identical to the first.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))

from docs import dataset as dataset_doc          # noqa: E402
from docs import licenses as licenses_doc        # noqa: E402
from docs import model_card as model_card_doc    # noqa: E402
from docs import readme as readme_doc            # noqa: E402
from docs import reproduce as reproduce_doc      # noqa: E402
from docs import sbom as sbom_doc                # noqa: E402
from docs.common import DOCS, Fmt, Resolver      # noqa: E402
from eval.common import check_manifest_settings  # noqa: E402

RUN_MANIFESTS = ("baseline", "cond1", "cond2")

DOCUMENTS = [
    ("README.md", readme_doc.render),
    ("docs/MODEL_CARD.md", model_card_doc.render),
    ("docs/DATASET.md", dataset_doc.render),
    ("docs/LICENSES.md", licenses_doc.render),
    ("docs/SBOM.md", sbom_doc.render),
    ("docs/REPRODUCE.md", reproduce_doc.render),
]


def gate_run_manifests() -> None:
    """Refuse to publish from a run whose manifest the scorers would refuse."""
    for run in RUN_MANIFESTS:
        path = REPO / "runs" / run / "manifest.json"
        if not path.exists():
            raise SystemExit(f"make docs: run manifest missing: {path}")
        check_manifest_settings(json.loads(path.read_text()))
    print(f"[1/4] run manifests pass the harness settings check: {', '.join(RUN_MANIFESTS)}")


def main() -> int:
    gate_run_manifests()

    R = Resolver()
    F = Fmt(R)
    print(f"[2/4] {len(R.data)} sources loaded")

    written = []
    for rel, render in DOCUMENTS:
        text = render(F)
        out = REPO / rel
        out.write_text(text, encoding="utf-8")
        written.append((rel, len(text.encode())))

    # The SPDX document is JSON, not markdown, and is produced by the same
    # renderer that wrote docs/SBOM.md so the two cannot disagree.
    spdx_path = REPO / "sbom.spdx.json"
    spdx_path.write_text(sbom_doc.spdx_json(F), encoding="utf-8")
    written.append(("sbom.spdx.json", spdx_path.stat().st_size))

    (DOCS / "trace.json").write_text(
        json.dumps(F.trace(), indent=1, ensure_ascii=False, sort_keys=False) + "\n",
        encoding="utf-8")

    for rel, size in written:
        print(f"[3/4] wrote {rel} ({size:,} bytes)")
    print(f"[4/4] docs/trace.json: {len(F.entries):,} traced numbers, "
          f"{len(F.allowed):,} distinct numeric tokens")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
