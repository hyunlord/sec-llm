"""`python -m ingest.verify_digests` -- recompute every per-file digest.

Independent of the ingesters on purpose: it reads the committed manifests, finds
the artifact each entry names, and recomputes the hash from the bytes on disk.
A manifest that asserts a digest it cannot back up fails here regardless of what
the code that wrote it believed.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))

from ingest.common.manifest import validate_manifest_files  # noqa: E402

MANIFESTS = REPO / "manifests"


def main(argv=None) -> int:
    files = sorted(MANIFESTS.glob("*.manifest.json"))
    if not files:
        print("ERROR: no manifests found", file=sys.stderr)
        return 2

    total_entries = total_problems = 0
    for mp in files:
        m = json.loads(mp.read_text())
        entries = m.get("files", [])
        problems = validate_manifest_files(m, REPO)
        total_entries += len(entries)
        total_problems += len(problems)
        n_file = sum(1 for e in entries if e.get("kind") == "file")
        n_dir = sum(1 for e in entries if e.get("kind") == "directory")
        status = "OK" if not problems else f"{len(problems)} PROBLEM(S)"
        print(f"{m['source_id']:9} {len(entries):>4} entries ({n_file} file, {n_dir} directory) -> {status}")
        for prob in problems:
            print(f"    {prob}")

    print(f"\n{total_entries} entries checked across {len(files)} manifests, {total_problems} problems")
    if total_problems:
        print("FAILED: at least one manifest asserts a digest it cannot back up")
        return 1
    print("ALL PER-FILE DIGESTS VERIFIED AGAINST THE ARTIFACTS ON DISK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
