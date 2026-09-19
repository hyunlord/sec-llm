"""Assemble manifests/datasets.manifest.json from the FINAL artifacts.

Written after contamination removal and length profiling, so the counts and
digests describe what is actually on disk. No wall-clock field anywhere -- a
re-run against the same inputs reproduces this file byte for byte.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from datasets import temporal  # noqa: E402
from datasets.common import MANIFESTS, OUT, REPO, file_sha256  # noqa: E402

TASKS = ("cve_to_cwe", "cvss_vector", "attack_technique", "structured_extract", "replay")


def main() -> int:
    build = json.loads((OUT / "build_stats.json").read_text())
    contam = json.loads((OUT / "contamination.json").read_text())
    lengths = json.loads((OUT / "lengths.json").read_text())
    lock = json.loads((REPO / "ingest" / "sources.lock.json").read_text())["sources"]

    files = {}
    for t in TASKS:
        d = OUT / t
        if not d.exists():
            continue
        for p in sorted(d.glob("*.jsonl")):
            n = sum(1 for _ in open(p, "rb"))
            files[f"{t}/{p.name}"] = {"sha256": file_sha256(p), "bytes": p.stat().st_size, "count": n}

    pins = {k: {kk: v.get(kk) for kk in ("pin_type", "commit_sha", "version", "tag", "snapshot_instant_utc") if v.get(kk)}
            for k, v in lock.items()}
    schemas = {p.stem: file_sha256(p) for p in sorted((REPO / "datasets" / "schemas").glob("*.json"))}

    manifest = {
        "schema_version": 1,
        "phase": "P3",
        "decisions": {
            "temporal_split": {
                "cutoff": temporal.CUTOFF,
                "pre_cutoff_eval_years": list(temporal.PRE_EVAL_YEARS),
                "eval_sample_per_period": temporal.EVAL_SAMPLE,
                "training_uses_only_pre_cutoff": True,
                "post_cutoff_unused_cves": build["split_counts_cve"].get(temporal.POST_UNUSED, 0),
                "split_counts_cve": build["split_counts_cve"],
                "split_counts_attack": build["split_counts_attack"],
            },
            "cwe_ground_truth": {
                "buckets": build["cwe_buckets"],
                "cwe_source_by_split": build["cwe_source_by_split"],
                "guard": build["cwe_guard"],
                "contested_structure": build["contested_structure"],
                "policy": "agree->label; one side->label with source; disagree->contested, excluded, reported; "
                          "placeholders absent; REJECTED excluded everywhere; multi-CWE excluded from the single-label task",
            },
            "replay": {"source": "replay_oasst2", **build["replay"]["budget"],
                       "parse": build["replay"]["parse"], "scan": build["replay"]["scan"],
                       "lang_counts": build["replay"]["lang_counts"]},
        },
        "tasks": build["tasks"],
        "contamination": contam,
        "lengths": lengths,
        "files": files,
        "schemas_sha256": schemas,
        "pins": pins,
        "determinism": ("Splits by stable hash under a fixed seed; templates by stable hash; sorted iteration "
                        "everywhere; no wall-clock field. Re-running against the same pins and P2 outputs "
                        "reproduces this manifest byte for byte."),
    }
    out = MANIFESTS / "datasets.manifest.json"
    out.write_bytes(json.dumps(manifest, indent=2, sort_keys=True, ensure_ascii=False).encode() + b"\n")
    print(f"wrote {out} ({len(files)} files)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
