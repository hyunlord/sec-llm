"""Per-source SHA256 manifest writer.

The one design decision that matters here: **a manifest contains no wall-clock
timestamp.** Gate 1 requires that re-running the ingester against the same pins
produces byte-identical manifests, and a `generated_at` field makes that
impossible by construction. Every timestamp in a manifest is derived from the
pin -- the commit date, the release date, the snapshot instant -- all of which
are fixed in the committed lock file. When the run happened is a property of the
run, recorded in reports/ingest.md; it is not a property of the data.

Records are hashed over their *source content only*, never over the lineage
envelope, because the envelope legitimately carries `retrieved_at` and would
otherwise make every run differ.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from .lineage import LINEAGE_FIELDS, canonical_json, file_sha256

SCHEMA_VERSION = 1

DETERMINISM_NOTE = (
    "This manifest contains no wall-clock field. All timestamps derive from the "
    "committed pin, so re-running the ingester against the same pin reproduces "
    "this file byte for byte. Run time is recorded in reports/ingest.md."
)


class ManifestBuilder:
    def __init__(
        self,
        *,
        source_id: str,
        source_name: str,
        source_url: str,
        pin: dict,
        content_type: str,
        license_block: dict,
        source_timestamp: str,
        notes: list | None = None,
    ):
        self.source_id = source_id
        self.source_name = source_name
        self.source_url = source_url
        self.pin = pin
        self.content_type = content_type
        self.license_block = license_block
        self.source_timestamp = source_timestamp
        self.notes = list(notes or [])
        self._hashes: list[str] = []
        self._entity_present = 0
        self._entity_missing = 0
        self._files: list[dict] = []
        self._entity_samples: list[str] = []

    def add_record(self, content_sha256: str, entity_id: str | None) -> None:
        self._hashes.append(content_sha256)
        if entity_id:
            self._entity_present += 1
            if len(self._entity_samples) < 5:
                self._entity_samples.append(str(entity_id))
        else:
            self._entity_missing += 1

    def add_file(self, path: Path, root: Path) -> dict:
        path = Path(path)
        entry = {
            "path": str(path.relative_to(root)).replace("\\", "/"),
            "sha256": file_sha256(path),
            "bytes": path.stat().st_size,
        }
        self._files.append(entry)
        return entry

    def add_file_entry(self, rel_path: str, sha256: str, size: int) -> None:
        self._files.append({"path": rel_path, "sha256": sha256, "bytes": int(size)})

    @property
    def record_count(self) -> int:
        return len(self._hashes)

    def records_digest(self) -> str:
        """Order-independent digest over every record's content hash.

        Sorted before hashing so filesystem iteration order -- which differs
        between macOS and Linux, and this code runs on both -- cannot change the
        result.
        """
        h = hashlib.sha256()
        for x in sorted(self._hashes):
            h.update(x.encode("ascii"))
        return h.hexdigest()

    def build(self) -> dict:
        total = self.record_count
        coverage = (self._entity_present / total) if total else 0.0
        return {
            "schema_version": SCHEMA_VERSION,
            "source_id": self.source_id,
            "source_name": self.source_name,
            "source_url": self.source_url,
            "content_type": self.content_type,
            "pin": self.pin,
            "source_timestamp": self.source_timestamp,
            "license": self.license_block,
            "counts": {
                "records": total,
                "entity_id_present": self._entity_present,
                "entity_id_missing": self._entity_missing,
                "files": len(self._files),
                "bytes": sum(f["bytes"] for f in self._files),
            },
            "entity_id_coverage": round(coverage, 6),
            "records_digest": self.records_digest(),
            "files": sorted(self._files, key=lambda f: f["path"]),
            "entity_id_samples": self._entity_samples,
            "lineage_fields": list(LINEAGE_FIELDS),
            "determinism": DETERMINISM_NOTE,
            "notes": self.notes,
        }

    def write(self, out_dir: Path) -> Path:
        out_dir = Path(out_dir)
        out_dir.mkdir(parents=True, exist_ok=True)
        out = out_dir / f"{self.source_id}.manifest.json"
        payload = self.build()
        # Deterministic serialization, trailing newline, sorted keys.
        out.write_bytes(
            json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False).encode("utf-8") + b"\n"
        )
        return out


def load_manifest(path: Path) -> dict:
    return json.loads(Path(path).read_text())
