"""Pull the comparable free text out of each record type.

Dedup and secret scanning both need "the text of this record", and what that
means differs per source. Keeping the extraction in one place means the two
stages can never disagree about what they are looking at.

The returned `text` is what gets canonicalized, hashed and shingled. `fields` is
the per-field breakdown the secret scanner needs so it can report which field a
finding came from.
"""

from __future__ import annotations


def _join(parts) -> str:
    return "\n".join(p for p in parts if p)


def _descriptions(node) -> list[str]:
    """CVE/NVD description arrays: [{lang, value}, ...], English first."""
    out = []
    if isinstance(node, list):
        for d in node:
            if isinstance(d, dict) and d.get("value"):
                lang = (d.get("lang") or "en").lower()
                out.append((0 if lang.startswith("en") else 1, d["value"]))
    return [v for _, v in sorted(out, key=lambda t: t[0])]


def _cwe_text(node) -> str:
    """CWE XML-derived dicts carry text under '#text' or plain strings."""
    if isinstance(node, str):
        return node
    if isinstance(node, dict):
        if "#text" in node:
            return str(node["#text"])
        return _join(_cwe_text(v) for v in node.values())
    if isinstance(node, list):
        return _join(_cwe_text(v) for v in node)
    return ""


def extract(content_type: str, content: dict) -> dict:
    """-> {"text": str, "fields": {name: str}, "refs": [url, ...]}"""
    fields: dict[str, str] = {}
    refs: list[str] = []

    if content_type == "cve_record_v5_json":
        cna = (content.get("containers") or {}).get("cna") or {}
        descs = _descriptions(cna.get("descriptions"))
        if descs:
            fields["description"] = descs[0]
        if cna.get("title"):
            fields["title"] = str(cna["title"])
        for ref in cna.get("references") or []:
            if isinstance(ref, dict):
                if ref.get("url"):
                    refs.append(ref["url"])
                if ref.get("name"):
                    fields.setdefault("reference_names", "")
                    fields["reference_names"] += str(ref["name"]) + "\n"
        for pt in cna.get("problemTypes") or []:
            for d in (pt.get("descriptions") or []):
                if d.get("description"):
                    fields.setdefault("problem_type", "")
                    fields["problem_type"] += str(d["description"]) + "\n"

    elif content_type == "nvd_cve_api_2_0_json":
        cve = content.get("cve") or {}
        descs = _descriptions(cve.get("descriptions"))
        if descs:
            fields["description"] = descs[0]
        for ref in cve.get("references") or []:
            if isinstance(ref, dict) and ref.get("url"):
                refs.append(ref["url"])

    elif content_type.startswith("cwe_"):
        for key in ("Description", "Extended_Description", "Background_Details"):
            if key in content:
                t = _cwe_text(content[key]).strip()
                if t:
                    fields[key.lower()] = t
        attrs = content.get("@attributes") or {}
        if attrs.get("Name"):
            fields["name"] = attrs["Name"]

    elif content_type.startswith("stix_"):
        if content.get("name"):
            fields["name"] = str(content["name"])
        if content.get("description"):
            fields["description"] = str(content["description"])
        for r in content.get("external_references") or []:
            if isinstance(r, dict):
                if r.get("url"):
                    refs.append(r["url"])
                if r.get("description"):
                    fields.setdefault("reference_descriptions", "")
                    fields["reference_descriptions"] += str(r["description"]) + "\n"

    text = _join(fields.get(k, "") for k in ("title", "name", "description", "extended_description"))
    if not text:
        text = _join(fields.values())
    return {"text": text, "fields": fields, "refs": refs}
