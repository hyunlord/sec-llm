"""Lineage schema for every ingested record.

The design constraint worth restating: a container's license and the license of
the content inside it are frequently different. NVD is the clearest case -- the
NVD's own analysis is a US Government work in the public domain, while the CVE
description embedded in the same JSON object originates from the CVE Program and
carries MITRE's terms. Collapsing that into one `license` column would erase the
distinction this project exists to track, so `source_license` (the container)
and `upstream_license` (the content) are separate and both required.

`entity_id` is the cross-source identity key: the CVE ID, the CWE ID, the ATT&CK
technique ID. It is what P2 uses to tell "the same entity appearing in two
sources" apart from "a genuine duplicate". It is the one field allowed to be
None, and only when the source genuinely provides no identifier -- coverage is
counted and reported rather than assumed.
"""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any

LINEAGE_FIELDS = (
    "source_id",
    "source_name",
    "source_url",
    "source_pin",
    "retrieved_at",
    "record_id",
    "entity_id",
    "content_type",
    "source_license",
    "upstream_license",
    "redistribution_status",
    "commercial_status",
    "contains_third_party_content",
    "pii_policy",
    "model_publication_status",
    "transform_history",
    "content_sha256",
)

# Only entity_id may be None, and only where the source provides no identifier.
NULLABLE_FIELDS = frozenset({"entity_id"})

# `not_addressed` and `unknown` are deliberately different answers:
#   not_addressed -- we read the source's licence and it does not speak to this
#                    question at all. The absence is the finding.
#   unknown       -- we have not established what the document says.
# Collapsing them would let "the licence is silent" masquerade as "we have not
# checked", or worse, let either masquerade as a permission.
REDISTRIBUTION_STATUS = frozenset(
    {"permitted", "permitted_with_attribution", "prohibited", "not_addressed", "unknown"}
)
COMMERCIAL_STATUS = frozenset(
    {"permitted", "permitted_with_attribution", "prohibited", "not_addressed", "unknown"}
)

# Whether a weight trained on this data may be published. This is the licence
# question that decides whether this project's final artifact can exist at all,
# so it is machine-readable per record rather than prose in a document -- P7
# has to answer it by query.
MODEL_PUBLICATION_STATUS = frozenset(
    {"permitted", "prohibited", "not_addressed", "unknown"}
)

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


class LineageError(ValueError):
    """Raised when a record's lineage is incomplete or malformed."""


def canonical_json(obj: Any) -> bytes:
    """Stable serialization for hashing.

    sort_keys and a fixed separator make the digest independent of dict
    ordering, so the same source content hashes the same on every run and on
    every platform. This is what makes the manifests reproducible.
    """
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def content_hash(obj: Any) -> str:
    return hashlib.sha256(canonical_json(obj)).hexdigest()


def file_sha256(path, chunk: int = 1 << 20) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        while True:
            b = fh.read(chunk)
            if not b:
                break
            h.update(b)
    return h.hexdigest()


def make_lineage(
    *,
    source_id: str,
    source_name: str,
    source_url: str,
    source_pin: str,
    retrieved_at: str,
    record_id: str,
    entity_id: str | None,
    content_type: str,
    source_license: str,
    upstream_license: str,
    redistribution_status: str,
    commercial_status: str,
    contains_third_party_content: bool,
    pii_policy: str,
    model_publication_status: str,
    content_sha256: str,
    transform_history: list | None = None,
) -> dict:
    """Build a lineage block. Every field is keyword-only and required.

    transform_history stays a list -- every later processing step appends to it.
    Collapsing it to a string would make the provenance chain unparseable the
    first time two transforms are applied.
    """
    return {
        "source_id": source_id,
        "source_name": source_name,
        "source_url": source_url,
        "source_pin": source_pin,
        "retrieved_at": retrieved_at,
        "record_id": record_id,
        "entity_id": entity_id,
        "content_type": content_type,
        "source_license": source_license,
        "upstream_license": upstream_license,
        "redistribution_status": redistribution_status,
        "commercial_status": commercial_status,
        "contains_third_party_content": bool(contains_third_party_content),
        "pii_policy": pii_policy,
        "model_publication_status": model_publication_status,
        "transform_history": list(transform_history or []),
        "content_sha256": content_sha256,
    }


def validate_lineage(lin: dict, *, where: str = "") -> None:
    """Hard assertion that nothing was silently defaulted to null.

    Gate 1 requires this to be enforced in code rather than by inspection, so
    this raises rather than warns and every ingester calls it on every record.
    """
    ctx = f" ({where})" if where else ""

    missing = [f for f in LINEAGE_FIELDS if f not in lin]
    if missing:
        raise LineageError(f"missing lineage fields{ctx}: {missing}")

    extra = [k for k in lin if k not in LINEAGE_FIELDS]
    if extra:
        raise LineageError(f"unexpected lineage fields{ctx}: {extra}")

    for f in LINEAGE_FIELDS:
        if f in NULLABLE_FIELDS:
            continue
        v = lin[f]
        if v is None:
            raise LineageError(f"lineage field '{f}' is None{ctx}; use an explicit value")
        if isinstance(v, str) and not v.strip():
            raise LineageError(f"lineage field '{f}' is empty{ctx}; use an explicit value")

    if not isinstance(lin["transform_history"], list):
        raise LineageError(f"transform_history must be a list{ctx}, got {type(lin['transform_history']).__name__}")
    if not isinstance(lin["contains_third_party_content"], bool):
        raise LineageError(f"contains_third_party_content must be a bool{ctx}")
    if lin["redistribution_status"] not in REDISTRIBUTION_STATUS:
        raise LineageError(f"redistribution_status '{lin['redistribution_status']}' not in {sorted(REDISTRIBUTION_STATUS)}{ctx}")
    if lin["commercial_status"] not in COMMERCIAL_STATUS:
        raise LineageError(f"commercial_status '{lin['commercial_status']}' not in {sorted(COMMERCIAL_STATUS)}{ctx}")
    if lin["model_publication_status"] not in MODEL_PUBLICATION_STATUS:
        raise LineageError(
            f"model_publication_status '{lin['model_publication_status']}' not in "
            f"{sorted(MODEL_PUBLICATION_STATUS)}{ctx}"
        )
    if not _SHA256_RE.match(lin["content_sha256"] or ""):
        raise LineageError(f"content_sha256 is not a lowercase hex sha256{ctx}: {lin['content_sha256']!r}")
    if lin["entity_id"] is not None and not str(lin["entity_id"]).strip():
        raise LineageError(f"entity_id present but empty{ctx}; use None when the source has no identifier")
