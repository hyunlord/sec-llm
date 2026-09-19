"""Decision 2 -- CWE ground truth.

The P2 entity view showed 394,957 CVEs in both sources and 13,562 where the
CNA-supplied CWE and NVD's analyst-assigned CWE disagree. This module turns that
into a per-CVE label with its provenance, or into a named reason for having no
label. It never picks a side in a disagreement: a contested label is not a label.

Buckets (every CVE lands in exactly one):
  agreed        both sources give the same single CWE            -> label, cwe_source=agreed
  nvd           only NVD gives a CWE (single)                    -> label, cwe_source=nvd
  cna           only the CNA gives a CWE (single)                -> label, cwe_source=cna
  contested     both give CWEs and the sets differ               -> NO label; reported, not scored
  multi_cwe     the available source(s) give >1 CWE              -> NO label; single-label task
  placeholder   only NVD-CWE-Other / NVD-CWE-noinfo etc.          -> NO label; placeholders are not labels
  none          no CWE anywhere                                  -> NO label
  rejected      cveMetadata.state == REJECTED                    -> excluded from every task
"""

from __future__ import annotations

LABELLED = ("agreed", "nvd", "cna")


def resolve(row: dict) -> dict:
    """-> {"bucket": str, "cwe_id": str|None, "cwe_source": str|None, "relation": str|None}"""
    if row.get("state") != "PUBLISHED":
        return {"bucket": "rejected", "cwe_id": None, "cwe_source": None, "relation": None}
    c, n = set(row.get("cna_cwes") or []), set(row.get("nvd_cwes") or [])
    if c and n:
        if c == n:
            if len(c) == 1:
                return {"bucket": "agreed", "cwe_id": next(iter(c)), "cwe_source": "agreed", "relation": "equal"}
            return {"bucket": "multi_cwe", "cwe_id": None, "cwe_source": "agreed", "relation": "equal_multi"}
        rel = "partial_overlap" if (c & n) else "disjoint"
        return {"bucket": "contested", "cwe_id": None, "cwe_source": None, "relation": rel}
    if c:
        if len(c) == 1:
            return {"bucket": "cna", "cwe_id": next(iter(c)), "cwe_source": "cna", "relation": "cna_only"}
        return {"bucket": "multi_cwe", "cwe_id": None, "cwe_source": "cna", "relation": "cna_only_multi"}
    if n:
        if len(n) == 1:
            return {"bucket": "nvd", "cwe_id": next(iter(n)), "cwe_source": "nvd", "relation": "nvd_only"}
        return {"bucket": "multi_cwe", "cwe_id": None, "cwe_source": "nvd", "relation": "nvd_only_multi"}
    if row.get("cna_cwe_placeholder") or row.get("nvd_cwe_placeholder"):
        return {"bucket": "placeholder", "cwe_id": None, "cwe_source": None, "relation": "placeholder_only"}
    return {"bucket": "none", "cwe_id": None, "cwe_source": None, "relation": None}
