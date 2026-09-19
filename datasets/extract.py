"""Build the per-CVE and per-technique tables every P3 decision reads from.

One row per entity, carrying everything the three decisions and four tasks
need: publish date, both sources' CWE sets with placeholders tracked
separately, the NVD v3.1 metric, the CNA's structured `affected` block, the
dedup decision on the record that supplies the input text, and the REJECTED
state. Built once, deterministically, then consumed read-only.
"""

from __future__ import annotations

import re
import sys
import time
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from datasets.common import (  # noqa: E402
    ATTACK_TABLE,
    CVE_TABLE,
    CWE_PLACEHOLDERS,
    INGESTED,
    PROCESSED,
    ensure_dirs,
    iter_jsonl,
    write_jsonl,
)
from process.canonical import canonicalize  # noqa: E402

CWE_RE = re.compile(r"CWE-\d+", re.I)
ATTACK_URL_RE = re.compile(r"https?://attack\.mitre\.org/[^\s)\]]+")
CITATION_RE = re.compile(r"\(Citation:[^)]*\)")
MD_LINK_RE = re.compile(r"\[([^\]]+)\]\((?:https?://attack\.mitre\.org/[^)]*)\)")


def _en_description(descs) -> str:
    if not isinstance(descs, list):
        return ""
    en = [d.get("value", "") for d in descs if isinstance(d, dict) and str(d.get("lang", "en")).lower().startswith("en")]
    any_ = [d.get("value", "") for d in descs if isinstance(d, dict)]
    return (en or any_ or [""])[0] or ""


def _cwe_sets(raw_values):
    """-> (informative_set, placeholder_seen: bool)"""
    inf, placeholder = set(), False
    for v in raw_values:
        v = str(v or "").strip().upper()
        if not v:
            continue
        if v in CWE_PLACEHOLDERS:
            placeholder = True
            continue
        for m in CWE_RE.findall(v):
            inf.add(m.upper())
    return inf, placeholder


def build_cve_table() -> dict:
    ensure_dirs()
    t0 = time.time()
    rows: dict[str, dict] = {}
    stats = Counter()

    # --- cve_list: identity, date, description, CNA CWE, affected, impacts ---
    for rec in iter_jsonl(INGESTED / "cve_list.jsonl"):
        lin, c = rec["lineage"], rec["content"]
        cid = lin["entity_id"]
        if not cid:
            continue
        meta = c.get("cveMetadata") or {}
        cna = (c.get("containers") or {}).get("cna") or {}
        raw_cwes = []
        for pt in cna.get("problemTypes") or []:
            for d in pt.get("descriptions") or []:
                if d.get("cweId"):
                    raw_cwes.append(d["cweId"])
                raw_cwes.extend(CWE_RE.findall(str(d.get("description") or "")))
        cna_cwes, cna_ph = _cwe_sets(raw_cwes)
        desc, _ = canonicalize(_en_description(cna.get("descriptions")))
        affected = []
        for a in cna.get("affected") or []:
            if not isinstance(a, dict):
                continue
            versions = []
            for v in a.get("versions") or []:
                if isinstance(v, dict) and v.get("version") and str(v.get("status", "affected")) == "affected":
                    versions.append(str(v["version"]))
            affected.append({
                "vendor": str(a.get("vendor") or ""),
                "product": str(a.get("product") or ""),
                "versions": versions,
                "default_status": a.get("defaultStatus"),
            })
        impacts = []
        for imp in cna.get("impacts") or []:
            for d in (imp.get("descriptions") or []):
                if d.get("value"):
                    impacts.append(str(d["value"]))
        rows[cid] = {
            "cve_id": cid,
            "state": meta.get("state"),
            "date_published": meta.get("datePublished"),
            "assigner": meta.get("assignerShortName"),
            "description": desc,
            "cna_cwes": sorted(cna_cwes),
            "cna_cwe_placeholder": cna_ph,
            "affected": affected,
            "impacts": impacts,
            "cve_list_record_id": lin["record_id"],
            "nvd_cwes": [],
            "nvd_cwe_placeholder": False,
            "nvd_description": "",
            "nvd_published": None,
            "cvss31": None,
            "cvss_versions_present": [],
        }
        stats["cve_list_rows"] += 1

    # --- nvd: analyst CWE, CVSS v3.1, its own description ---
    for rec in iter_jsonl(INGESTED / "nvd.jsonl"):
        lin, c = rec["lineage"], rec["content"]
        cid = lin["entity_id"]
        cve = c.get("cve") or {}
        row = rows.get(cid)
        if row is None:
            row = rows[cid] = {
                "cve_id": cid, "state": None, "date_published": None, "assigner": None,
                "description": "", "cna_cwes": [], "cna_cwe_placeholder": False,
                "affected": [], "impacts": [], "cve_list_record_id": None,
            }
            stats["nvd_only_rows"] += 1
        raw = [d.get("value") for w in (cve.get("weaknesses") or []) for d in (w.get("description") or [])]
        nvd_cwes, nvd_ph = _cwe_sets(raw)
        metrics = cve.get("metrics") or {}
        present = [k for k in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2") if metrics.get(k)]
        cvss31 = None
        if metrics.get("cvssMetricV31"):
            # Prefer the NVD-authored entry over a CNA-supplied one when both exist.
            entries = sorted(metrics["cvssMetricV31"], key=lambda e: 0 if e.get("type") == "Primary" else 1)
            d = entries[0].get("cvssData") or {}
            cvss31 = {k: d.get(k) for k in (
                "version", "vectorString", "baseScore", "baseSeverity",
                "attackVector", "attackComplexity", "privilegesRequired", "userInteraction",
                "scope", "confidentialityImpact", "integrityImpact", "availabilityImpact",
            )}
        row.update({
            "nvd_cwes": sorted(nvd_cwes),
            "nvd_cwe_placeholder": nvd_ph,
            "nvd_description": canonicalize(_en_description(cve.get("descriptions")))[0],
            "nvd_published": cve.get("published"),
            "nvd_vuln_status": cve.get("vulnStatus"),
            "cvss31": cvss31,
            "cvss_versions_present": present,
        })
        if row["date_published"] is None:
            row["date_published"] = cve.get("published")
        stats["nvd_rows"] += 1

    # --- dedup decision on the record that supplies the input text ---
    for d in iter_jsonl(PROCESSED / "decisions.jsonl"):
        if d["source_id"] != "cve_list":
            continue
        row = rows.get(d["entity_id"])
        if row is None:
            continue
        row["dedup_keep"] = bool(d["dedup_keep"])
        row["dedup_stage"] = d["dedup_stage"]
        row["dedup_cluster_id"] = d["dedup_cluster_id"]
        row["dedup_role"] = d["dedup_role"]
        row["dedup_similarity"] = d.get("dedup_similarity")

    for row in rows.values():
        row.setdefault("dedup_keep", True)
        row.setdefault("dedup_stage", "none")
        row.setdefault("dedup_cluster_id", None)
        row.setdefault("dedup_role", None)
        row.setdefault("dedup_similarity", None)
        row["year"] = int(row["date_published"][:4]) if row.get("date_published") else None

    n, sha = write_jsonl(CVE_TABLE, (rows[k] for k in sorted(rows)))
    stats["rows_written"] = n
    return {"rows": n, "sha256": sha, "stats": dict(stats), "elapsed_seconds": round(time.time() - t0, 1)}


def clean_attack_description(text: str) -> tuple[str, dict]:
    """Strip answer leaks from an ATT&CK description.

    Descriptions carry markdown links to attack.mitre.org/techniques/T1059/001 --
    frequently the technique's own page -- which hands the model the label. Link
    text is kept, URLs to attack.mitre.org are removed, and (Citation: ...) markers
    (which add nothing and sometimes embed technique names) are dropped. What was
    removed is counted so the card can say how much the input was altered.
    """
    counts = {"attack_links": 0, "citations": 0}
    def _link(m):
        counts["attack_links"] += 1
        return m.group(1)
    out = MD_LINK_RE.sub(_link, text or "")
    out, n = ATTACK_URL_RE.subn("", out)
    counts["attack_links"] += n
    out, n = CITATION_RE.subn("", out)
    counts["citations"] = n
    out, _ = canonicalize(out)
    return out, counts


def build_attack_table() -> dict:
    ensure_dirs()
    t0 = time.time()
    keep: dict[str, bool] = {}
    for d in iter_jsonl(PROCESSED / "decisions.jsonl"):
        if d["source_id"] == "attack":
            keep[d["record_id"]] = bool(d["dedup_keep"])

    rows = []
    stats = Counter()
    seen_ids = set()
    for rec in iter_jsonl(INGESTED / "attack.jsonl"):
        lin, c = rec["lineage"], rec["content"]
        if c.get("type") != "attack-pattern":
            continue
        tid = lin["entity_id"]
        if not tid or not tid.startswith("T"):
            stats["no_technique_id"] += 1
            continue
        # The same technique appears in more than one domain bundle; keep the
        # first (sorted by record id later) and count the rest.
        if tid in seen_ids:
            stats["duplicate_across_domains"] += 1
            continue
        seen_ids.add(tid)
        if c.get("revoked") or c.get("x_mitre_deprecated"):
            stats["revoked_or_deprecated"] += 1
            continue
        desc, removed = clean_attack_description(c.get("description") or "")
        rows.append({
            "technique_id": tid,
            "stix_id": c.get("id"),
            "name": c.get("name"),
            "description": desc,
            "leak_removed": removed,
            "is_subtechnique": bool(c.get("x_mitre_is_subtechnique")),
            "created": c.get("created"),
            "modified": c.get("modified"),
            "domains": c.get("x_mitre_domains") or [],
            "tactics": sorted({p.get("phase_name") for p in (c.get("kill_chain_phases") or []) if p.get("phase_name")}),
            "dedup_keep": keep.get(lin["record_id"], True),
            "record_id": lin["record_id"],
            "year": int(c["created"][:4]) if c.get("created") else None,
        })
        stats["techniques"] += 1
    rows.sort(key=lambda r: r["technique_id"])
    n, sha = write_jsonl(ATTACK_TABLE, rows)
    return {"rows": n, "sha256": sha, "stats": dict(stats), "elapsed_seconds": round(time.time() - t0, 1)}


if __name__ == "__main__":
    import json
    print(json.dumps({"cve": build_cve_table(), "attack": build_attack_table()}, indent=2))
