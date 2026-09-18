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
import re
from pathlib import Path

from .lineage import LINEAGE_FIELDS, canonical_json, file_sha256

SCHEMA_VERSION = 2

REPO_ROOT = Path(__file__).resolve().parents[2]

# digest_type -> required hex length. A git commit identifier is SHA-1 (40 hex)
# and is recorded as what it is; it is never widened to look like a SHA-256.
DIGEST_TYPES = {"sha256": 64, "git_commit_sha": 40}

DETERMINISM_NOTE = (
    "This manifest contains no wall-clock field. All timestamps derive from the "
    "committed pin, so re-running the ingester against the same pin reproduces "
    "this file byte for byte. Run time is recorded in reports/ingest.md."
)

INTEGRITY_NOTE_PER_FILE = (
    "Every entry with kind='file' carries a sha256 that is the actual SHA-256 of "
    "that one file; `python -m ingest.verify_digests` recomputes them from disk. "
    "A digest is never padded, widened, or synthesised to fit a field."
)

INTEGRITY_NOTE_COMMIT_ANCHORED = (
    "This source carries no per-file sha256: per-file digests for the record count "
    "here would bloat the manifest past usefulness. Content integrity is instead "
    "anchored to two real digests -- the git commit SHA, which is itself a Merkle "
    "root over the entire tree, and records_digest, a SHA-256 over every record's "
    "content hash. Neither is synthesised, and no field claims to be a SHA-256 of "
    "something it is not."
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
        no_entity_id_types: list | None = None,
    ):
        self.source_id = source_id
        self.source_name = source_name
        self.source_url = source_url
        self.pin = pin
        self.content_type = content_type
        self.license_block = license_block
        self.source_timestamp = source_timestamp
        self.notes = list(notes or [])
        # Content types the source genuinely does not give an identifier. Kept
        # explicit so the headline coverage number can be read honestly: a STIX
        # bundle is 80% relationship objects, and counting those as "missing"
        # makes a complete ingest look like a broken one.
        self.no_entity_id_types = set(no_entity_id_types or ())
        self._hashes: list[str] = []
        self._entity_present = 0
        self._entity_missing = 0
        self._files: list[dict] = []
        self._entity_samples: list[str] = []
        self._not_identifiable = 0

    def add_record(self, content_sha256: str, entity_id: str | None, content_type: str | None = None) -> None:
        self._hashes.append(content_sha256)
        if content_type in self.no_entity_id_types:
            self._not_identifiable += 1
        if entity_id:
            self._entity_present += 1
            if len(self._entity_samples) < 5:
                self._entity_samples.append(str(entity_id))
        else:
            self._entity_missing += 1

    def add_file(self, path: Path, root: Path) -> dict:
        path = Path(path)
        self.add_file_entry(
            str(path.relative_to(root)).replace("\\", "/"),
            file_sha256(path),
            "sha256",
            path.stat().st_size,
        )
        return self._files[-1]

    def add_file_entry(
        self,
        rel_path: str,
        digest: str,
        digest_type: str,
        size: int,
        *,
        kind: str = "file",
    ) -> None:
        """Record an artifact with a digest stored under a key that names it.

        digest_type is explicit and becomes the key, so a git commit identifier
        is written as `git_commit_sha` and never as `sha256`. Padding a 40-hex
        git SHA-1 out to 64 characters to fit a field named sha256 produces a
        value that passes a hex-shaped validator and is a forgery; that is
        exactly what this signature exists to make impossible.
        """
        if digest_type not in DIGEST_TYPES:
            raise ValueError(f"unknown digest_type {digest_type!r}; expected one of {sorted(DIGEST_TYPES)}")
        expected_len = DIGEST_TYPES[digest_type]
        if not re.fullmatch(f"[0-9a-f]{{{expected_len}}}", digest or ""):
            raise ValueError(
                f"{digest_type} must be exactly {expected_len} lowercase hex characters, got {digest!r}"
            )
        if kind not in ("file", "directory"):
            raise ValueError(f"kind must be 'file' or 'directory', got {kind!r}")
        if kind == "directory" and digest_type == "sha256":
            raise ValueError(
                f"refusing to attach a sha256 to a directory entry ({rel_path!r}); "
                "a sha256 must be the digest of one named file"
            )
        # Shape alone cannot catch a forgery: a git SHA-1 zero-padded to 64
        # characters is indistinguishable from a real SHA-256 by inspection.
        # The only check that works is recomputing from the bytes, so when the
        # artifact is on disk that is what happens -- at write time, not only in
        # the after-the-fact verifier.
        if kind == "file" and digest_type == "sha256":
            target = REPO_ROOT / rel_path
            if target.exists() and target.is_file():
                actual = file_sha256(target)
                if actual != digest:
                    raise ValueError(
                        f"refusing to record a sha256 that is not the digest of {rel_path}:\n"
                        f"  claimed {digest}\n  actual  {actual}"
                    )
            elif target.exists() and target.is_dir():
                raise ValueError(
                    f"{rel_path} is a directory but was passed as kind='file' with a sha256"
                )

        entry = {"path": rel_path, "kind": kind, digest_type: digest}
        # A field named `bytes` describes one file. A directory gets a field
        # that says it is a directory total.
        entry["bytes" if kind == "file" else "bytes_on_disk"] = int(size)
        self._files.append(entry)

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
        identifiable = total - self._not_identifiable
        coverage_identifiable = (self._entity_present / identifiable) if identifiable else 0.0
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
                "records_without_expected_entity_id": max(0, identifiable - self._entity_present),
                "identifiable_records": identifiable,
                "files": sum(1 for f in self._files if f.get("kind") == "file"),
                "directories": sum(1 for f in self._files if f.get("kind") == "directory"),
                # Kept apart on purpose: a directory total and a sum of file
                # sizes are different measurements and adding them together
                # would produce a number that describes nothing.
                "bytes": sum(f.get("bytes", 0) for f in self._files if f.get("kind") == "file"),
                "bytes_on_disk": sum(
                    f.get("bytes_on_disk", 0) for f in self._files if f.get("kind") == "directory"
                ),
            },
            "entity_id_coverage": round(coverage, 6),
            "entity_id_coverage_identifiable": round(coverage_identifiable, 6),
            "content_types_without_entity_id": sorted(self.no_entity_id_types),
            "records_digest": self.records_digest(),
            "files": sorted(self._files, key=lambda f: f["path"]),
            "entity_id_samples": self._entity_samples,
            "lineage_fields": list(LINEAGE_FIELDS),
            "determinism": DETERMINISM_NOTE,
            "integrity": (
                INTEGRITY_NOTE_COMMIT_ANCHORED
                if any(f.get("kind") == "directory" for f in self._files)
                else INTEGRITY_NOTE_PER_FILE
            ),
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


def validate_manifest_files(manifest: dict, repo_root: Path) -> list[str]:
    """Structural + cryptographic check of every file entry in a manifest.

    Returns a list of problems; empty means the manifest's integrity claims hold.
    Every `sha256` must be the actual SHA-256 of the single file it names, and a
    directory entry must not carry one at all.
    """
    problems: list[str] = []
    for e in manifest.get("files", []):
        path = e.get("path", "<no path>")
        kind = e.get("kind")
        if kind not in ("file", "directory"):
            problems.append(f"{path}: missing or invalid 'kind' ({kind!r})")
            continue

        if kind == "directory":
            if "sha256" in e:
                problems.append(f"{path}: directory entry carries a sha256, which cannot be meaningful")
            if "git_commit_sha" in e and not re.fullmatch(r"[0-9a-f]{40}", e["git_commit_sha"]):
                problems.append(f"{path}: git_commit_sha is not 40 lowercase hex characters")
            if "bytes" in e:
                problems.append(f"{path}: directory entry uses 'bytes'; expected 'bytes_on_disk'")
            continue

        digest = e.get("sha256")
        if not digest:
            problems.append(f"{path}: file entry has no sha256")
            continue
        if not re.fullmatch(r"[0-9a-f]{64}", digest):
            problems.append(f"{path}: sha256 is not 64 lowercase hex characters")
            continue
        target = repo_root / path
        if not target.exists():
            problems.append(f"{path}: artifact is not on disk; cannot verify the digest")
            continue
        if target.is_dir():
            problems.append(f"{path}: entry is marked 'file' but the path is a directory")
            continue
        actual = file_sha256(target)
        if actual != digest:
            problems.append(f"{path}: sha256 mismatch\n    manifest {digest}\n    actual   {actual}")
        size = target.stat().st_size
        if e.get("bytes") != size:
            problems.append(f"{path}: bytes {e.get('bytes')} but the file is {size}")
    return problems
