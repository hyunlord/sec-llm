"""JSONL writer that validates lineage on every record before it hits disk.

Validation is here rather than in each ingester so no ingester can forget it --
Gate 1 requires the assertion to be in code, and a check that each caller has to
remember is a check that eventually is not run.
"""

from __future__ import annotations

import json
from pathlib import Path

from .lineage import validate_lineage


class RecordWriter:
    def __init__(self, path: Path, source_id: str):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.source_id = source_id
        self._fh = None
        self.count = 0

    def __enter__(self):
        self._fh = open(self.path, "w", encoding="utf-8")
        return self

    def write(self, lineage: dict, content) -> None:
        validate_lineage(lineage, where=f"{self.source_id} record {self.count}")
        self._fh.write(
            json.dumps({"lineage": lineage, "content": content}, ensure_ascii=False, sort_keys=True) + "\n"
        )
        self.count += 1

    def __exit__(self, *exc):
        if self._fh:
            self._fh.close()
        return False
