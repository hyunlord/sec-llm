"""Stage 3 -- identity grouping. This is not deduplication.

The same CVE appears in cve_list and in nvd. Those are not duplicates: they are
two sources describing one entity, and the difference between them is
information. Collapsing them would destroy the comparison that makes this corpus
worth building.

So this stage groups by entity_id and records where the sources disagree.
`field_conflicts` is the output that matters. A CNA-supplied CWE mapping that
disagrees with NVD's analyst-assigned CWE is surfaced, never resolved -- P3
decides which to treat as ground truth, and P2's job is to make it visible that
the choice exists at all.
"""

from __future__ import annotations

import json
import re
import sys
import time
from collections import Counter, defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from process.common import (  # noqa: E402
    ENTITY_PATH,
    INGESTED,
    iter_jsonl,
    peak_rss_bytes,
    write_jsonl,
)

CWE_RE = re.compile(r"CWE-\d+", re.I)


def _cve_list_fields(content: dict) -> dict:
    cna = (content.get("containers") or {}).get("cna") or {}
    meta = content.get("cveMetadata") or {}
    cwes = set()
    for pt in cna.get("problemTypes") or []:
        for d in pt.get("descriptions") or []:
            if d.get("cweId"):
                cwes.add(d["cweId"].upper())
            for m in CWE_RE.findall(str(d.get("description") or "")):
                cwes.add(m.upper())
    cvss = None
    for m in cna.get("metrics") or []:
        for k, v in (m or {}).items():
            if isinstance(v, dict) and v.get("baseScore") is not None:
                cvss = float(v["baseScore"])
    return {
        "cwe_ids": sorted(cwes),
        "cvss_base_score": cvss,
        "state": meta.get("state"),
        "date_published": meta.get("datePublished"),
        "assigner": meta.get("assignerShortName"),
    }


def _nvd_fields(content: dict) -> dict:
    cve = content.get("cve") or {}
    cwes = set()
    for w in cve.get("weaknesses") or []:
        for d in w.get("description") or []:
            val = str(d.get("value") or "")
            for m in CWE_RE.findall(val):
                cwes.add(m.upper())
    cvss = None
    metrics = cve.get("metrics") or {}
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        if metrics.get(key):
            d = metrics[key][0].get("cvssData") or {}
            if d.get("baseScore") is not None:
                cvss = float(d["baseScore"])
                break
    return {
        "cwe_ids": sorted(cwes),
        "cvss_base_score": cvss,
        "state": cve.get("vulnStatus"),
        "date_published": cve.get("published"),
        "assigner": cve.get("sourceIdentifier"),
    }


EXTRACTORS = {
    "cve_record_v5_json": _cve_list_fields,
    "nvd_cve_api_2_0_json": _nvd_fields,
}

# CWE values that carry no mapping information. Treating these as a real
# disagreement would inflate the conflict count with noise.
NON_INFORMATIVE_CWE = {"NVD-CWE-NOINFO", "NVD-CWE-OTHER", "CWE-NOINFO", "CWE-OTHER", "UNSURE"}


def build_entities() -> dict:
    t0 = time.time()
    by_entity: dict[str, dict] = defaultdict(lambda: {"sources": {}, "records": []})

    for sid in ("cve_list", "nvd"):
        path = INGESTED / f"{sid}.jsonl"
        if not path.exists():
            continue
        n = 0
        for rec in iter_jsonl(path):
            lin = rec["lineage"]
            eid = lin["entity_id"]
            if not eid:
                continue
            ct = lin["content_type"]
            fn = EXTRACTORS.get(ct)
            if fn is None:
                continue
            ent = by_entity[eid]
            ent["sources"][sid] = fn(rec["content"])
            ent["records"].append(f"{sid}:{lin['record_id']}")
            n += 1
            if n % 100_000 == 0:
                print(f"    {sid}: {n:,} ({time.time()-t0:.0f}s)", flush=True)
        print(f"  {sid}: {n:,} entity records")

    multi = 0
    conflict_counts = Counter()
    entities_with_conflicts = 0
    cwe_conflict_examples = []
    rows = []

    for eid in sorted(by_entity):
        ent = by_entity[eid]
        srcs = sorted(ent["sources"])
        conflicts = []

        if len(srcs) > 1:
            multi += 1
            a, b = ent["sources"][srcs[0]], ent["sources"][srcs[1]]

            # CWE mapping: the conflict that matters for the CVE->CWE task.
            ca = {c for c in a["cwe_ids"] if c.upper() not in NON_INFORMATIVE_CWE}
            cb = {c for c in b["cwe_ids"] if c.upper() not in NON_INFORMATIVE_CWE}
            if ca and cb and ca != cb:
                conflicts.append({
                    "field": "cwe_ids",
                    srcs[0]: sorted(ca),
                    srcs[1]: sorted(cb),
                    "relation": "disjoint" if not (ca & cb) else "partial_overlap",
                })
                conflict_counts["cwe_ids"] += 1
                if len(cwe_conflict_examples) < 20:
                    cwe_conflict_examples.append(
                        {"entity_id": eid, srcs[0]: sorted(ca), srcs[1]: sorted(cb)}
                    )
            elif bool(ca) != bool(cb):
                conflicts.append({
                    "field": "cwe_ids",
                    srcs[0]: sorted(ca),
                    srcs[1]: sorted(cb),
                    "relation": "present_in_one_source_only",
                })
                conflict_counts["cwe_ids_one_sided"] += 1

            # CVSS base score: a numeric disagreement beyond rounding.
            sa, sb = a["cvss_base_score"], b["cvss_base_score"]
            if sa is not None and sb is not None and abs(sa - sb) > 0.05:
                conflicts.append({
                    "field": "cvss_base_score", srcs[0]: sa, srcs[1]: sb,
                    "relation": "numeric_difference", "delta": round(abs(sa - sb), 2),
                })
                conflict_counts["cvss_base_score"] += 1
            elif (sa is None) != (sb is None):
                conflict_counts["cvss_base_score_one_sided"] += 1

            if conflicts:
                entities_with_conflicts += 1

        rows.append({
            "entity_id": eid,
            "sources": srcs,
            "record_ids": sorted(ent["records"]),
            "field_conflicts": conflicts,
        })

    n_written = write_jsonl(ENTITY_PATH, rows)
    return {
        "entities": n_written,
        "entities_in_multiple_sources": multi,
        "entities_in_one_source_only": n_written - multi,
        "entities_with_field_conflicts": entities_with_conflicts,
        "conflicts_by_field": dict(conflict_counts),
        "cwe_conflict_examples": cwe_conflict_examples,
        "elapsed_seconds": round(time.time() - t0, 1),
        "peak_rss_bytes": peak_rss_bytes(),
        "note": (
            "Identity grouping is NOT deduplication. Records grouped here keep "
            "dedup_stage='identity' and dedup_keep=true on every member: two sources "
            "describing one entity are not redundant, and the disagreement between them "
            "is the information this stage exists to surface."
        ),
    }


if __name__ == "__main__":
    print(json.dumps({k: v for k, v in build_entities().items() if k != "cwe_conflict_examples"}, indent=2))
